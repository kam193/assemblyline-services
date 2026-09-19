from service.extractor import Conversation, Extractor


def _layer(
    tcp_stream=0,
    protocols="eth:ethertype:ip:tcp:tls",
    src="10.0.0.1",
    dst="93.184.216.34",
    sport="40000",
    dport="443",
    http_host=None,
    http_uri=None,
    sni=None,
):
    layers = {
        "tcp_stream": [str(tcp_stream)],
        "frame_protocols": [protocols],
        "ip_src": [src],
        "tcp_srcport": [sport],
        "ip_dst": [dst],
        "tcp_dstport": [dport],
    }
    if http_host is not None:
        layers["http_host"] = [http_host]
        layers["http_request_uri"] = [http_uri or "/"]
    if sni is not None:
        layers["tls_handshake_extensions_server_name"] = sni if isinstance(sni, list) else [sni]
    return {"layers": layers}


class TestConversationFromDict:
    def test_from_dict_sni_only_sets_domain(self):
        conv = Conversation.from_dict(_layer(sni="sni.example.com"))

        assert conv.snis == ["sni.example.com"]
        assert conv.hosts == []
        assert conv.domains == ["sni.example.com"]

    def test_from_dict_no_sni_leaves_domain_unset(self):
        conv = Conversation.from_dict(_layer(protocols="eth:ethertype:ip:tcp"))

        assert conv.snis == []
        assert conv.domains == []

    def test_from_dict_multiple_snis_all_kept(self):
        conv = Conversation.from_dict(_layer(sni=["first.example.com", "second.example.net"]))

        assert conv.snis == ["first.example.com", "second.example.net"]
        assert conv.domains == ["first.example.com", "second.example.net"]

    def test_from_dict_duplicate_snis_deduplicated(self):
        conv = Conversation.from_dict(_layer(sni=["dup.example.com", "dup.example.com"]))

        assert conv.snis == ["dup.example.com"]

    def test_from_dict_http_and_sni_same_domain_is_deduplicated(self):
        conv = Conversation.from_dict(
            _layer(
                protocols="eth:ethertype:ip:tcp:http",
                dport="80",
                http_host="example.com",
                sni="example.com",
            )
        )

        assert conv.domains == ["example.com"]

    def test_from_dict_http_and_sni_different_domains_both_kept(self):
        conv = Conversation.from_dict(
            _layer(
                protocols="eth:ethertype:ip:tcp:http",
                dport="80",
                http_host="cdn.example.com",
                sni="front-domain.example.net",
            )
        )

        assert conv.domains == ["cdn.example.com", "front-domain.example.net"]


class TestConversationUpdate:
    def test_update_keeps_sni_from_first_packet(self):
        conv = Conversation.from_dict(_layer(sni="first.example.com"))

        conv.update(_layer(protocols="eth:ethertype:ip:tcp"))

        assert conv.snis == ["first.example.com"]

    def test_update_sets_sni_from_later_packet(self):
        conv = Conversation.from_dict(_layer(protocols="eth:ethertype:ip:tcp"))

        conv.update(_layer(sni="later.example.com"))

        assert conv.snis == ["later.example.com"]

    def test_update_accumulates_distinct_snis_across_packets(self):
        conv = Conversation.from_dict(_layer(sni="first.example.com"))

        conv.update(_layer(sni="second.example.net"))

        assert conv.snis == ["first.example.com", "second.example.net"]
        assert conv.domains == ["first.example.com", "second.example.net"]

    def test_update_ignores_repeated_sni(self):
        conv = Conversation.from_dict(_layer(sni="first.example.com"))

        conv.update(_layer(sni="first.example.com"))

        assert conv.snis == ["first.example.com"]


class TestExtractorGetIocs:
    def test_get_iocs_includes_sni_only_domain(self):
        extractor = Extractor("/nonexistent.pcap")
        conv = Conversation.from_dict(_layer(sni="sni-only.example.com", dst="1.2.3.4"))
        extractor._conversations[("tcp", conv.stream_id)] = conv

        ips, domains, uris = extractor.get_iocs()

        assert ips == {"1.2.3.4"}
        assert domains == {"sni-only.example.com"}
        assert uris == set()
