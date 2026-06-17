import base64
import json
import unittest

from core.server_parser import ServerParseError, parse_outbound, parse_server_uri


UUID = "00000000-0000-4000-8000-000000000000"


class ServerParserTests(unittest.TestCase):
    def test_vless_reality_keeps_plus_signs_in_query_values(self) -> None:
        profile = parse_server_uri(
            f"vless://{UUID}@example.com:443"
            "?security=reality&type=ws&path=/api+a&host=front+host.example"
            "&sni=front.example&fp=chrome&pbk=public-key&sid=abcd#VLESS+Demo",
            subscription_id="sub",
        )

        self.assertEqual(profile.protocol, "vless")
        self.assertEqual(profile.name, "VLESS+Demo")
        self.assertEqual(profile.subscription_id, "sub")
        self.assertEqual(profile.params["path"], "/api+a")
        self.assertEqual(profile.params["host"], "front+host.example")
        self.assertEqual(profile.params["security"], "reality")

    def test_password_protocol_aliases_parse_expected_params(self) -> None:
        trojan = parse_server_uri("trojan://secret@example.com:443?security=tls&sni=front.example#Trojan")
        hysteria = parse_server_uri("hy2://hy-pass@example.com:8443?sni=hy.example&obfs=salamander#HY2")
        tuic = parse_server_uri(f"tuic://{UUID}:tuic-pass@example.com:443?sni=tuic.example#TUIC")

        self.assertEqual(trojan.protocol, "trojan")
        self.assertEqual(trojan.params["password"], "secret")
        self.assertEqual(trojan.params["sni"], "front.example")
        self.assertEqual(hysteria.protocol, "hysteria2")
        self.assertEqual(hysteria.params["password"], "hy-pass")
        self.assertEqual(hysteria.params["obfs"], "salamander")
        self.assertEqual(tuic.protocol, "tuic")
        self.assertEqual(tuic.uuid, UUID)
        self.assertEqual(tuic.params["password"], "tuic-pass")

    def test_vmess_base64_json_and_uri_forms(self) -> None:
        payload = {
            "v": "2",
            "ps": "VMess JSON",
            "add": "vmess.example.com",
            "port": "443",
            "id": UUID,
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "host": "front.example.com",
            "path": "/ws",
            "tls": "tls",
            "sni": "sni.example.com",
        }
        link = "vmess://" + base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        json_profile = parse_server_uri(link)
        uri_profile = parse_server_uri(f"vmess://{UUID}@uri.example.com:443?security=auto&type=grpc#VMess URI")

        self.assertEqual(json_profile.name, "VMess JSON")
        self.assertEqual(json_profile.protocol, "vmess")
        self.assertEqual(json_profile.params["type"], "ws")
        self.assertEqual(json_profile.params["security"], "tls")
        self.assertEqual(json_profile.params["sni"], "sni.example.com")
        self.assertEqual(uri_profile.params["vmess_security"], "auto")

    def test_shadowsocks_sip002_and_base64_forms(self) -> None:
        sip002 = parse_server_uri("ss://2022-blake3-aes-128-gcm:secret@example.com:8388#SS2022")
        encoded = base64.b64encode(b"aes-128-gcm:secret@example.org:8388").decode("ascii")
        legacy = parse_server_uri(f"ss:///{encoded}#Legacy")

        self.assertEqual(sip002.protocol, "shadowsocks")
        self.assertEqual(sip002.params["method"], "2022-blake3-aes-128-gcm")
        self.assertEqual(sip002.params["password"], "secret")
        self.assertEqual(legacy.address, "example.org")
        self.assertEqual(legacy.params["method"], "aes-128-gcm")

    def test_wireguard_alias_uri_extracts_peer_params(self) -> None:
        profile = parse_server_uri(
            "wg://private-key@wg.example.com:51820"
            "?peer_public_key=peer-key&local_address=172.16.0.2%2F32%2Cfd00%3A%3A2%2F128#WG"
        )

        self.assertEqual(profile.protocol, "wireguard")
        self.assertEqual(profile.address, "wg.example.com")
        self.assertEqual(profile.port, 51820)
        self.assertEqual(profile.params["private_key"], "private-key")
        self.assertEqual(profile.params["peer_public_key"], "peer-key")
        self.assertEqual(profile.params["local_address"], "172.16.0.2/32,fd00::2/128")

    def test_parse_json_outbound_preserves_tls_transport_and_mux_metadata(self) -> None:
        profile = parse_outbound(
            {
                "type": "vless",
                "tag": "json-vless",
                "server": "json.example.com",
                "server_port": 443,
                "uuid": UUID,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": "front.example.com",
                    "utls": {"fingerprint": "chrome"},
                    "reality": {"enabled": True, "public_key": "pbk", "short_id": "sid"},
                },
                "transport": {"type": "grpc", "service_name": "svc"},
                "multiplex": {"enabled": True, "protocol": "smux", "max_connections": 4},
            },
            subscription_id="sub",
        )

        self.assertEqual(profile.protocol, "vless")
        self.assertEqual(profile.name, "json-vless")
        self.assertEqual(profile.params["security"], "reality")
        self.assertEqual(profile.params["sni"], "front.example.com")
        self.assertEqual(profile.params["fp"], "chrome")
        self.assertEqual(profile.params["pbk"], "pbk")
        self.assertEqual(profile.params["sid"], "sid")
        self.assertEqual(profile.params["type"], "grpc")
        self.assertEqual(profile.params["serviceName"], "svc")
        self.assertEqual(profile.params["mux"], "true")
        self.assertEqual(profile.params["muxMaxConnections"], "4")

    def test_rejects_unsupported_scheme_bad_uuid_and_bad_port(self) -> None:
        with self.assertRaisesRegex(ServerParseError, "Неподдерживаемый"):
            parse_server_uri("http://example.com")
        with self.assertRaisesRegex(ServerParseError, "UUID"):
            parse_server_uri("vless://not-a-uuid@example.com:443")
        with self.assertRaisesRegex(ServerParseError, "порт"):
            parse_server_uri(f"vless://{UUID}@example.com:not-a-port")


if __name__ == "__main__":
    unittest.main()
