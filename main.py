# Made with 💖 by @3d3n.c

import ast
import base64
import zlib
import sys


class DeobfExceptions:
    class FoundValue(Exception):
        def __init__(self, value):
            self.value = value

    class NoB64String(Exception):
        def __init__(self, message="No base64 encoded string found in the code."):
            super().__init__(message)

    class InvalidBase64(Exception):
        def __init__(self, message="Invalid base64 encoded string."):
            super().__init__(message)
    
    class DecompressionError(Exception):
        def __init__(self, message="Error decompressing the base64 decoded string."):
            super().__init__(message)


class B64Visitor(ast.NodeVisitor):
    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "b64decode"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "base64"
        ):
            if node.args and isinstance(node.args[0], ast.Constant):
                raise DeobfExceptions.FoundValue(node.args[0].value)
        self.generic_visit(node)


class Deobfuscator:
    
    def __init__(self, input: str, output: str = "output.py"):
        self.input = input
        self.output = output

        self.tree = self.get_code(input)
        self.string = self.extract_string(self.tree)

        if not self.string:
            raise DeobfExceptions.NoB64String()

        self.deobfuscated_code = self.deobfuscate(self.string)
    
    def get_code(self, file: str) -> ast.AST:
        with open(file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        return tree

    def extract_string(self, tree: ast.AST) -> str:
        try:
            B64Visitor().visit(tree)
        except DeobfExceptions.FoundValue as e:
            return e.value
        return None

    def deobfuscate(self, code: str) -> str:
        try:
            compressed_code = base64.b64decode(code)
        except:
            raise DeobfExceptions.InvalidBase64()
        try:
            decompressed_code = zlib.decompress(compressed_code).decode('utf-8')
        except:
            raise DeobfExceptions.DecompressionError()
        return decompressed_code

    def save_output(self, output: str):
        with open(output, "w", encoding="utf-8") as f:
            f.write(self.deobfuscated_code)
        print(f"\033[92mDeobfuscated code saved to {output}\033[0m")


if __name__ == "__main__":
    if "-h" in sys.argv or "--help" in sys.argv:
        filename = sys.argv[0]
        print(f"\033[93mUsage: python {filename} <input_file> <output_file>\033[0m")
        print(f"\033[93mDefault output file is 'output.py'\033[0m")
        sys.exit(0)

    if len(sys.argv) not in [2, 3]:
        filename = sys.argv[0]
        print(f"\033[93mUsage: python {filename} <input_file> <output_file>\033[0m")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "output.py"

    try:
        deobfuscator = Deobfuscator(input_file, output_file)
        deobfuscator.save_output(deobfuscator.output)
    except Exception as e:
        print(f"\033[91m{e}\033[0m")
        sys.exit(1)
