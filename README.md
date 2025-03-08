# Custom services for AssemblyLine 4

A set of custom services extending the capabilities of [AssemblyLine 4](https://github.com/CybercentreCanada/assemblyline).
They are created as a hobby project, so please do not expect production quality. They should work with the latest
version of AssemblyLine 4.

## Installation

To install a service, copy the content of the appropriate `service_manifest.yml` and paste it in your AssemblyLine
instance, in the *Administration* -> *Services* -> *Add a service* (green plus button) window. The service will be
installed and ready to use, updates will be handles as any other service.

## Services

### ASAR Extractor

Simple service extracting [ASAR archives](https://www.electronjs.org/docs/latest/tutorial/asar-archives)
using official [asar tool](https://www.npmjs.com/package/@electron/asar) from Electron. By default, node modules
are omitted from the extracted files, but it can be configured using submission parameters.

### ASTGrep

Service using [AST-Grep](https://ast-grep.github.io/) to analyze the source code. Currently used only for
obfuscation detection and deobfuscation. At the moment, only builtin rules are supported and the service is focused on Python code.

### ClamAV

This service uses the ClamAV antivirus engine to scan files for viruses. It leverages the daemon mode to keep db
definitions in memory and avoid reloading them for each scan. Support for Freshclam and directly downloading custom
databases, both as AL-native update service. Both ClamAV and Freshclam can be fully configured.

### File Similarity

Comparing TLSH hashes to find similar files. It supports external lists in CSV as well as files badlisted in the
AssemblyLine system. Both are updated periodically, as native AL update services. Not recommended for use with large
number of badlisted files, it's just a linear comparison.

### Hashlookup

It performs hash lookups to identify well-known good and bad files. It be used to avoid analyzing well-known
files. Responses are cached. Currently supported services:

- [CIRCL Hashlookup](https://www.circl.lu/services/hashlookup/): identify well-known files and return trust
  score. DNS queries are used to check for the hash, and then REST API to get more details. It could be an
  online alternative to loading NIST NSRL database (and more) into Safelist service.
- [Cymru Malware Hash Registr](https://www.team-cymru.com/mhr): identify well-known malware files. Only
  DNS queries are used. This service does not offer extended details (e.g. no malware name).

### Network Information

Service to get information about IPs and domains. Currently supported:

- IP data from MMDB files (you can configure your own, the default one is [GeoOpen](https://cra.circl.lu/opendata/geo-open/)),
- WHOIS data for domains, including domains extracted from URIs. Results are cached.

Supported heuristics:

- newly created domains (based on WHOIS data).

### OOPreview (deprecated)

  > [!NOTE]
  > Deprecated as the same preview builder is now used by the official AL DocumentPreview
  > service (starting version 4.5.0.stable36).

Simple service that uses [OnlyOffice Document Builder](https://api.onlyoffice.com/docbuilder/basic)
to generate documents previews, with the high compatibility with Microsoft Office formats. Supported
generating the preview for the first or all pages.

### PCAP Extractor

This service list TCP flows from a pcap file using Tshark. If supported by Tshark, it can also extract files.
It tries to set as much as possible tags, and respect safelisting to avoid unnecessary operations.

Supported heuristics:

- external HTTP/non-HTTP connections,
- data exfiltration threshold (based on total data sent out).

### Python Magic

Designed to help with analysis of Python artifacts. Currently supported:

- unpacking PyInstaller executables (using [pyinstxtractor-ng](https://github.com/pyinstxtractor/pyinstxtractor-ng)),
- extracting declared dependencies and matching them against configurable lists of suspicious and malicious packages,
- detecting overwriting popular packages paths.

### RemoteAV

Allows simple scan using a remote antivirus. It requires a host with a running HTTP service exposing API (see attached `openapi.json` for definition).
Server implementation is not published yet.

### Semgrep

Service using [Semgrep](https://semgrep.dev) OSS to analyze code for malicious activity. Currently in the alpha stage.
By default configured to use rules from [GuardDog](https://github.com/DataDog/guarddog) project.

### Simple Downloader

Very simple service to download URLs, without running a whole browser. User-agent can be configured.

Additional features:

  - extract URLs from directory listings as URI files allowing to download automatically download them.

## License

Although the code is licensed under the MIT license, the services may use third-party data or dependencies.
Please respect the applicable licenses.
