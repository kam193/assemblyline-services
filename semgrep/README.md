# Semgrep

Service using [Semgrep](https://semgrep.dev) OSS to analyze code for malicious activity.

Currently in the alpha stage. Be default utilizes `semgrep lsp` to avoid loading rules
on every request, but it can be changed to `semgrep scan` if needed.
By default configured to use rules from [GuardDog](https://github.com/DataDog/guarddog) project.