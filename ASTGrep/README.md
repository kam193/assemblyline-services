# ASTGrep

Service using [AST-Grep](https://ast-grep.github.io/) to analyze code for obfuscation.

Currently in the alpha stage. Be default utilizes `sg lsp` to avoid loading rules
on every request.

## Usage without Assembylyline

The `controller` module can be used as a standalone python module. It's intended for debugging purposes,
but can be used to deobfuscate code without having to run the service.

You can either install requirements from `requirements.txt` and call the `controller` module directly,
or just install the module with `pip install .`: this will also install the `deobfuscate` script.

CLI uses the [Typer](https://typer.tiangolo.com/) library, so you can even install the bash completion.

### CLI usage

```bash

$ python -m service.controller --help
<OR>
$ deobfuscate --help

 Usage: deobfuscate [OPTIONS] FILE

╭─ Arguments ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    file      PATH  Path to the file to deobfuscate [default: None] [required]                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --lang                                     TEXT     Language as in AL convention [default: code/python]                                │
│ --verbose               --no-verbose                Verbose output [default: no-verbose]                                               │
│ --final-only            --no-final-only             Print only final layer [default: no-final-only]                                    │
│ --output                                   TEXT     Output file [default: None]                                                        │
│ --max-iterations                           INTEGER  Maximum iterations [default: None]                                                 │
│ --timeout                                  INTEGER  Obfuscation timeout in seconds [default: 120]                                      │
│ --install-completion                                Install completion for the current shell.                                          │
│ --show-completion                                   Show completion for the current shell, to copy it or customize the installation.   │
│ --help                                              Show this message and exit.                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### Example usage

```bash
$ deobfuscate --final-only path/to/obfuscated/file.py > deobfuscated.py
```