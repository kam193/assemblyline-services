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

## Disclaimer

Deobfuscation process is not perfect. It relies on finding patterns and replacing them with the original code, as well as
removing comments and other parts of the code that appear to only serve as an obstruction. This process can sometimes
modify the original code in unexpected ways or remove some parts. Please note that, depending on the obfuscation method,
the returned code may not be exactly the same as the original one.

If you want to see what was done to the code, you can use the `--verbose` option to see the applied rules. By using the
`--max-iterations` with increasing values you can also see all the intermediate steps.

The code is always printed to stdout, while logs and other CLI output to stderr.
