import json
import os
import subprocess
from typing import Dict, List, Optional
import ast
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FunctionVisitor(ast.NodeVisitor):
    def __init__(self):
        self.functions = []
        
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
        dependencies = []
        for ancestor in ast.walk(node):
            if isinstance(ancestor, ast.Import):
                for name in ancestor.names:
                    dependencies.append(name.name)
            elif isinstance(ancestor, ast.ImportFrom):
                dependencies.append(ancestor.module)
        
        function_info = {
            'name': node.name,
            'signature': {
                'args': args,
                'return_type': return_type
            },
            'docstring': docstring,
            'dependencies': list(set(dependencies))
        }
        
        self.functions.append(function_info)
        
        self.generic_visit(node)

def extract_functions_from_file(file_path: str) -> List[Dict]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())
            
        visitor = FunctionVisitor()
        visitor.visit(tree)
        return visitor.functions
    except Exception as e:
        logger.error(f"Error processing {file_path}: {str(e)}")
        return []

def get_python_files() -> List[str]:
    result = subprocess.run(['git', 'ls-files', '*.py'], 
                          capture_output=True, 
                          text=True)
    return result.stdout.strip().split('\n')

def extract_branch_metadata() -> Dict:
    metadata = {}
    
    # Get all branches
    result = subprocess.run(['git', 'branch', '--no-color'], 
                          capture_output=True, 
                          text=True)
    branches = [b.strip().replace('* ', '') for b in result.stdout.split('\n') if b.strip()]
    
    for branch in branches:
        logger.info(f"Processing branch: {branch}")
        
        # Checkout branch
        subprocess.run(['git', 'checkout', branch], 
                      capture_output=True)
        
        branch_data = {}
        python_files = get_python_files()
        
        for file_path in python_files:
            if file_path and os.path.exists(file_path):
                functions = extract_functions_from_file(file_path)
                if functions:
                    branch_data[file_path] = functions
        
        if branch_data:
            metadata[branch] = branch_data
    
    # Return to original branch
    subprocess.run(['git', 'checkout', '-'], capture_output=True)
    
    return metadata

def main():
    os.makedirs('.local', exist_ok=True)
    
    metadata = extract_branch_metadata()
    
    output_path = '.local/function-metadata.json'
    with open(output_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    logger.info(f"Function metadata written to {output_path}")

if __name__ == '__main__':
    main()
