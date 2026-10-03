# PCAP Extractor

Service to extract data from PCAP files. Currently, it's mostly focused on TCP streams, especially HTTP(S).
Underlying tool is `tshark` (maybe changed to zeek in the future).
The service tries to tag as much as possible data as well as respect safelisting
to limit the amount of data extracted.

Supported heuristics:

- external HTTP/non-HTTP connections,
- data exfiltration threshold (based on total data sent out).

Note: Currently, the service is not always able to extract or tag all data from the PCAP.

## Safelisting and non-scoring conversations

A TCP conversation can be excluded from scoring/extraction through three mechanisms:

1. **System safelist** - exact `network.dynamic.domain`/`network.dynamic.ip`/`network.dynamic.uri`
   values known to the AssemblyLine safelist. A conversation is safelisted if all its domains,
   or all its URIs, or its destination IP, match.
2. **Service settings** (`no_score_domains`, `no_score_ips` config) - exact-match domains/IPs that
   are still extracted and tagged, but don't trigger a heuristic.
3. **Network rules** (this service's update source) - YAML rules carrying domain/URI regexes. Delivered as AssemblyLine signature sources.

   Each rule:

   ```yaml
   name: windows-update          # unique within the source
   action: safelist | no_score
   domains: ["<regex>", ...]     # matched with fullmatch, against domain incl. TLS SNI
   uris: ["<regex>", ...]        # matched with fullmatch, against the full URI
   ```

   At least one of `domains`/`uris` is required; multiple rule documents in one file are
   separated by `---`. Patterns are compiled with [RE2](https://github.com/google/re2) - no lookaround or
   backreferences.

   `fullmatch` is anchored at both ends, so a subdomain needs to be written explicitly, e.g.
   `(?:.+\.)?example\.com` to match both `example.com` and `sub.example.com`.

   - `safelist`: the conversation is safelisted if all its domains match, or all its URIs
     match.
   - `no_score`: the conversation is non-scoring if all its domains match, or all its URIs
     match.
   - A safelist match (system or rule) always takes priority over a non-scoring one.

## Dealing with timeouts

For bigger files, service may not be able to do everything during the limited time. Possible workarounds:

1. Increase the timeout in the service.
2. Do not extract data streams (each stream requires a separate `tshark` call).
3. Safelist IPs/domains to skip extracting data from them.
4. Limit the number of analyzed packets.
