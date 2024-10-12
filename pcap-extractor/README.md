# PCAP Extractor

Service to extract data from PCAP files. Currently, it's mostly focused on TCP streams, especially HTTP(S).
Underlying tool is `tshark` (maybe changed to zeek in the future).
The service tries to tag as much as possible data as well as respect safelisting
to limit the amount of data extracted.

Supported heuristics:

- external HTTP/non-HTTP connections,
- data exfiltration threshold (based on total data sent out).

Note: Currently, the service is not always able to extract or tag all data from the PCAP.

## Dealing with timeouts

For bigger files, service may not be able to do everything during the limited time. Possible workarounds:

1. Increase the timeout in the service.
2. Do not extract data streams (each stream requires a separate `tshark` call).
3. Safelist IPs/domains to skip extracting data from them.
4. Limit the number of analyzed packets.
