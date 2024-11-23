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

TODO:

Renaming ambiguous variables (?)

# ruleid: python-obfuscation-ambiguous-variable-name
(
    OO0oo0O0oOoO0OoooO,
    JLLLIJJILJLILIJLLLJI,
    O0000OOOO000ooO00OoO,
    OoO0OoooO0OOOO000OooOO0,
    IIlIllllIlIIlllIIl,
) = 1, 2, 3, 4, 5

# ruleid: python-obfuscation-ambiguous-variable-name
lambda nnnnnmmmnnmnmmnmnnnm: aaa

# ruleid: python-obfuscation-ambiguous-variable-name
__4319848022592 = 52015194899669

pattern-either:
            - pattern-regex: "[1lI]{10,}"
            - pattern-regex: "[0Oo]{10,}"
            - pattern-regex: "[mn]{10,}"
            - pattern-regex: "[IJl]{10,}"
            - pattern-regex: "_{1,}[0-9]{10,}"