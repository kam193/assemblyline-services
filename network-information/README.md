# Network Information

This service is designed to get information about IPs and domains.

You can configure whether to enable or disable MMDB or WHOIS data, as well as to set per-submission
which tags (static, dynamic, both or none) should be checked.

Currently supported:
 - IP information using MMDB files. You can configure any MMDB and as much as you want,
  free data are offered e.g. by [MaxMind](https://www.maxmind.com/) and [IPInfo.io](https://ipinfo.io/).
  It's primarily designed for Geolocation data, but providers offer different information in the format.
 - WHOIS data for domains, including domains extracted from URIs. Underline the standard `whois` command
  is used. Results are cached for a configurable time, by default 7 days.

Planned:
  - RIPE IP data,
