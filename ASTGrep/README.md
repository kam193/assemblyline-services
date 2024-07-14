# ASTGrep

Service using [AST-Grep](https://ast-grep.github.io/) OSS to analyze code for obfuscation.

Currently in the alpha stage. Be default utilizes `sg lsp` to avoid loading rules
on every request.

TODO:
    - rule updates
    - refactor steps definition
    - support for non-obfuscation rules ?