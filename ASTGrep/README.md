# ASTGrep

Service using [AST-Grep](https://ast-grep.github.io/) to analyze code for obfuscation.

Currently in the alpha stage. Be default utilizes `sg lsp` to avoid loading rules
on every request.

## Usage without Assembylyline

The `controller` module can be used as a standalone python module. It's intended for debugging purposes,
but can be used to deobfuscate code without having to run the service.

First, install requirements from `requirements.txt`. Then, you can use the `controller` module to deobfuscate:

```bash

$ python -m service.controller -h

usage: controller.py [-h] [--lang LANG] [--verbose] [--final-only] [--output OUTPUT] [--max-iterations MAX_ITERATIONS] file

positional arguments:
  file                  File path

options:
  -h, --help            show this help message and exit
  --lang LANG, -l LANG  Language as in AL convention
  --verbose             Verbose output
  --final-only          Print only final layer
  --output OUTPUT       Output file
  --max-iterations MAX_ITERATIONS
                        Maximum iterations
```