# Hashlookup

It performs hash lookups to identify well-known good and bad files. It be used to avoid analyzing well-known
files. Responses are cached. Currently supported services:
- [CIRCL Hashlookup](https://www.circl.lu/services/hashlookup/): identify well-known files and return trust
  score. DNS queries are used to check for the hash, and then REST API to get more details. It could be an
  online alternative to loading NIST NSRL database (and more) into Safelist service.
- [Cymru Malware Hash Registr](https://www.team-cymru.com/mhr): identify well-known malware files. Only
  DNS queries are used. This service does not offer extended details (e.g. no malware name).
