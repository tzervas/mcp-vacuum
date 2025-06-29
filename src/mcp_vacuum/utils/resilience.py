"""
Resilience utilities like Circuit Breaker.
"""
import asyncio
import time
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

class CircuitBreakerState(Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

class CircuitBreakerOpenError(Exception):
    """
    Raised when an operation is attempted while the CircuitBreaker is in the OPEN state.
    Indicates that the service is considered unavailable and calls are being rejected
    to prevent further failures and allow time for recovery.
    """
    def __init__(self, message: str = "Circuit breaker is OPEN. Call rejected.", remaining_time: float = 0):
        super().__init__(message)
        self.remaining_time = remaining_time # Approximate time until breaker might transition to HALF_OPEN

class CircuitBreaker:
    """
    A simple asynchronous Circuit Breaker implementation.
    """
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout_seconds: float = 30.0,
        half_open_max_successes: int = 2, # Number of successful trials to fully close
        name: str | None = None # For logging
    ):
        if failure_threshold < 1:
            raise ValueError("Failure threshold must be at least 1.")
        if recovery_timeout_seconds <= 0:
            raise ValueError("Recovery timeout must be positive.")
        if half_open_max_successes < 1:
            raise ValueError("Half-open max successes must be at least 1.")

        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self.half_open_max_successes = half_open_max_successes
        self.name = name or f"cb-{id(self)}" # Unique enough name for logging

        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float | None = None
        self._half_open_success_count = 0

        self._lock = asyncio.Lock() # To protect state transitions
        self.logger = logger.bind(circuit_breaker_name=self.name)
        self.logger.info("CircuitBreaker initialized", state=self._state.value, threshold=failure_threshold, timeout=recovery_timeout_seconds)

    @property
    def state(self) -> CircuitBreakerState:
        return self._state

    async def _open_circuit(self):
        async with self._lock:
            if self._state == CircuitBreakerState.OPEN: # Already open
                return
            self._state = CircuitBreakerState.OPEN
            self._last_failure_time = time.monotonic()
            self.logger.warning("Circuit breaker OPENED.")

    async def _close_circuit(self):
        async with self._lock:
            if self._state == CircuitBreakerState.CLOSED: # Already closed
                return
            self._state = CircuitBreakerState.CLOSED
            self._failure_count = 0
            self._half_open_success_count = 0
            self._last_failure_time = None
            self.logger.info("Circuit breaker CLOSED.")

    async def _try_half_open(self):
        async with self._lock:
            if self._state != CircuitBreakerState.OPEN: # Can only go to half-open from open
                return
            self._state = CircuitBreakerState.HALF_OPEN
            self._half_open_success_count = 0
            self.logger.info("Circuit breaker transitioned to HALF_OPEN.")

    async def call(self, func: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Executes the given awaitable function, protected by the circuit breaker.
        """
        await self._check_state_and_update()

        if self._state == CircuitBreakerState.OPEN:
            open_duration = time.monotonic() - (self._last_failure_time or 0)
            remaining = self.recovery_timeout_seconds - open_duration
            raise CircuitBreakerOpenError(remaining_time=max(0, remaining))

        # If CLOSED or HALF_OPEN, attempt the call
        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception:
            # Only count specific types of exceptions as failures if needed.
            # For now, any exception from `func` is a failure.
            await self._on_failure()
            raise # Re-raise the original exception

    async def _check_state_and_update(self):
        """Checks if the state needs to be transitioned (e.g., OPEN to HALF_OPEN)."""
        async with self._lock: # Protect read-modify-write of state
            if self._state == CircuitBreakerState.OPEN:
                if self._last_failure_time and \
                   (time.monotonic() - self._last_failure_time) > self.recovery_timeout_seconds:
                    # Recovery timeout has passed, move to HALF_OPEN
                    # This transition happens implicitly when _try_half_open is called
                    # by the next call attempt after timeout.
                    # To be more proactive, a background task could do this, but that adds complexity.
                    # For now, transition on next call after timeout.
                    self._state = CircuitBreakerState.HALF_OPEN
                    self._half_open_success_count = 0
                    self.logger.info("Circuit breaker recovery timeout expired, moving to HALF_OPEN on next call.")

    async def _on_success(self):
        async with self._lock:
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._half_open_success_count += 1
                if self._half_open_success_count >= self.half_open_max_successes:
                    await self._close_circuit() # Transition to CLOSED
                else:
                    self.logger.debug("HALF_OPEN call successful", success_count=self._half_open_success_count)
            elif self._state == CircuitBreakerState.CLOSED:
                # If it was closed and successful, reset failure count (though it should be 0)
                if self._failure_count > 0:
                    self.logger.debug("Successful call in CLOSED state, resetting failure count.")
                    self._failure_count = 0
                    self._last_failure_time = None


    async def _on_failure(self):
        async with self._lock:
            if self._state == CircuitBreakerState.HALF_OPEN:
                # Failure in HALF_OPEN state, re-open the circuit immediately
                self.logger.warning("Call failed in HALF_OPEN state. Re-opening circuit.")
                await self._open_circuit()
            elif self._state == CircuitBreakerState.CLOSED:
                self._failure_count += 1
                self._last_failure_time = time.monotonic() # Record time of last failure for OPEN state timeout
                self.logger.debug("Call failed in CLOSED state.", failure_count=self._failure_count, threshold=self.failure_threshold)
                if self._failure_count >= self.failure_threshold:
                    await self._open_circuit() # Transition to OPEN

    async def __aenter__(self):
        # This allows using the circuit breaker as an async context manager for a block of code.
        # However, the primary usage is via `call` method for individual functions.
        # If used as context manager, the block itself is the `func`.
        await self._check_state_and_update()
        if self._state == CircuitBreakerState.OPEN:
            open_duration = time.monotonic() - (self._last_failure_time or 0)
            remaining = self.recovery_timeout_seconds - open_duration
            raise CircuitBreakerOpenError(remaining_time=max(0, remaining))
        return self # Not strictly necessary to return self

    async def __aexit__(self, exc_type: type[BaseException] | None,
                        exc_value: BaseException | None,
                        traceback: Any | None):
        if exc_type is not None: # An exception occurred within the `async with` block
            # Don't double-count if it was CircuitBreakerOpenError from __aenter__
            if not isinstance(exc_value, CircuitBreakerOpenError):
                 await self._on_failure()
        else: # No exception, success
            await self._on_success()


# Example usage (conceptual):
# async def my_flaky_operation():
#     # ... do something that might fail ...
#     if random.random() < 0.3: # 30% chance of failure
#         raise ValueError("Operation failed")
#     return "Operation successful"

# async def main():
#     cb = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=5, name="MyServiceCB")
#     for i in range(20):
#         try:
#             print(f"Attempt {i+1}: ", end="")
#             # Example 1: Using call method
#             result = await cb.call(my_flaky_operation)
#             # Example 2: Using as context manager
#             # async with cb:
#             #    result = await my_flaky_operation()
#             print(result)
#         except CircuitBreakerOpenError as e:
#             print(f"Circuit OPEN. Try again in {e.remaining_time:.2f}s.")
#         except ValueError as e:
#             print(f"Operation error: {e}")

#         print(f"  CB State: {cb.state.value}, Failures: {cb._failure_count}, HalfOpenSuccesses: {cb._half_open_success_count}")
#         await asyncio.sleep(0.5 if cb.state != CircuitBreakerState.OPEN else 1.0)

# if __name__ == "__main__":
#    asyncio.run(main())
