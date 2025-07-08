import json
import os
import subprocess
from typing import Dict, List, Optional
import ast
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FunctionVisitor(ast.NodeVisitor):
    def __init__(self, module_node):
        self.functions = []
        self.module_node = module_node
        
    def visit_FunctionDef(self, node):
        # Extract function signature
        args = []
        for arg in node.args.args:
            arg_info = {
                'name': arg.arg,
                'type': ast.unparse(arg.annotation) if hasattr(arg, 'annotation') and arg.annotation else None
            }
            args.append(arg_info)
            
        # Extract return type
        return_type = ast.unparse(node.returns) if node.returns else None
        
        # Extract docstring
        docstring = ast.get_docstring(node)
        
        # Extract dependencies from imports
        # Collect module-level imports
        module_imports = []
        for n in ast.walk(self.module_node):
            if isinstance(n, ast.Import):
                module_imports.extend(name.name for name in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module:
                module_imports.append(n.module)

        # Collect function-level imports
        function_imports = []
        for ancestor in ast.walk(node):
            if isinstance(ancestor, ast.Import):
                function_imports.extend(name.name for name in ancestor.names)
            elif isinstance(ancestor, ast.ImportFrom) and ancestor.module:
                function_imports.append(ancestor.module)

        # Combine and deduplicate
        dependencies = list(set(module_imports + function_imports))
        
        function_info = {
            'name': node.name,
            'signature': {
                'args': args,
                'return_type': return_type
            },
            'docstring': docstring,
            'dependencies': dependencies
        }
        
        self.functions.append(function_info)
        
        self.generic_visit(node)

def extract_functions_from_file(file_path: str) -> List[Dict]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
            
        module_node = ast.parse(source_code)
        visitor = FunctionVisitor(module_node)
        visitor.visit(module_node)
        return visitor.functions
    except Exception as e:
        logger.error(f'Error processing {file_path}: {str(e)}')
        return []

def get_python_files() -> List[str]:
    result = subprocess.run(['git', 'ls-files', '*.py'], 
                          capture_output=True, 
                          text=True)
    return result.stdout.strip().split('\n')

def extract_branch_metadata() -> Dict:
    metadata = {}
    
    # Get current branch and ensure it's clean
    current_branch = subprocess.run(
        ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
        capture_output=True,
        text=True,
        check=True
    ).stdout.strip()
    
    # Check for uncommitted changes
    status_result = subprocess.run(
        ['git', 'status', '--porcelain'],
        capture_output=True,
        text=True,
        check=True
    )
    
    if status_result.stdout.strip():
        logger.error('Working directory has uncommitted changes. Please commit or stash them first.')
        return metadata
    
    try:
        # Get all branches
        result = subprocess.run(
            ['git', 'branch', '--no-color'],
            capture_output=True,
            text=True,
            check=True
        )
        branches = [b.strip().replace('* ', '') for b in result.stdout.split('\n') if b.strip()]
        
        for branch in branches:
            logger.info(f'Processing branch: {branch}')
            
            # Checkout branch in detached HEAD state to avoid issues
            checkout_result = subprocess.run(
                ['git', 'checkout', '--detach', branch],
                capture_output=True,
                text=True
            )
            
            if checkout_result.returncode != 0:
                logger.error(f'Failed to checkout branch {branch}: {checkout_result.stderr}')
                continue
            
            branch_data = {}
            python_files = get_python_files()
            
            for file_path in python_files:
                if file_path and os.path.exists(file_path):
                    functions = extract_functions_from_file(file_path)
                    if functions:
                        branch_data[file_path] = functions
            
            if branch_data:
                metadata[branch] = branch_data
    
    finally:
        # Always return to original branch
        subprocess.run(
            ['git', 'checkout', current_branch],
            capture_output=True,
            check=True
        )
    
    return metadata

def main():
    os.makedirs('.local', exist_ok=True)
    
    metadata = extract_branch_metadata()
    
    output_path = '.local/function-metadata.json'
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    
    logger.info(f'Function metadata written to {output_path}')

if __name__ == '__main__':
    main()
