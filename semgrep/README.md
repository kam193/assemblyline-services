# Semgrep

Service using [Semgrep](https://semgrep.dev) OSS to analyze code for malicious activity.

Currently in the alpha stage. Be default utilizes `semgrep lsp` to avoid loading rules
on every request, but it can be changed to `semgrep scan` if needed.
By default configured to use rules from [GuardDog](https://github.com/DataDog/guarddog) project.

Set `USE_OPENGREP: true` in the service config to run [Opengrep](https://github.com/opengrep/opengrep) instead of Semgrep. The binary is pinned in `opengrep.lock.json`; update it with `make update-opengrep`.
