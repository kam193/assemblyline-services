# PCAP Extractor

tcpflow - https://linux.die.net/man/1/tcpflow

Extract flows from pcap file

https://osqa-ask.wireshark.org/questions/56164/extract-payload-from-tcp-stream/ - how to extract streams using tshark

https://tshark.dev/export/export_regular/ - export files (but not streams) using tshark
https://www.comparitech.com/net-admin/decrypt-ssl-with-wireshark/
https://tshark.dev/export/export_tls/

https://scapy.readthedocs.io/en/latest/advanced_usage.html# - python tool to analyze packets

https://ask.wireshark.org/question/12318/tlsssl-pcap-with-key-save-decrypted-output-to-pcap-file-without-the-attach-key/ - editcap usage to embed key in pcap file

editcap --inject-secrets tls,<file-with-exported-keys> <original.pcap> <new.pcap>

tshark -r new.pcap -o tls.keylog_file:ssl.log -Q -z follow,tls,yaml,0 > out.yaml

tshark -r dump_with_secrets.pcap -Q -Y usb -z conv,tcp - list connections

tshark -r dump_with_secrets.pcap -q -2 -R "tcp.port in {80,443}" -z conv,tcp

tshark -r dump_with_secrets.pcap -q -z conv,tcp

Flow:

1. tshark -r dump_with_secrets.pcap -q -z conv,tcp,"tcp.port not in {80,443}"
2. For each stream:
   1. tshark -Q -r dump_with_secrets.pcap -z follow,tcp,ascii,172.17.0.2:37620,10.0.0.172:443
   2. Save to file and extract, add IPs as IoCs
3. tshark -r dump_with_secrets.pcap -q -z conv,tcp,"tcp.port in {80,443}"
4. For each stream:
   1. tshark -Q -r dump_with_secrets.pcap -2 -R "ip.addr in {172.17.0.2,34.107.221.82} and tcp.port in {49002,80}" --export-objects http,out4
   2. tshark -Q -r dump_with_secrets.pcap -z follow,http,ascii,172.17.0.2:49002,34.107.221.82:80 -> extract HTTP headers
   3. if 1. didn't extract anything, extract the whole stream


https://github.com/python-hyper/h11 - HTTP/1.1 parser