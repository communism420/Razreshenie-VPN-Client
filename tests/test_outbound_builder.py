import unittest

from core.outbound_builder import OutboundBuildError, OutboundBuilder
from models.profile import VlessProfile


def server(protocol: str, **kwargs) -> VlessProfile:
    params = kwargs.pop("params", {})
    return VlessProfile(
        id=f"{protocol}-test",
        name=f"{protocol} test",
        protocol=protocol,
        address=kwargs.pop("address", "example.com"),
        port=kwargs.pop("port", 443),
        uuid=kwargs.pop("uuid", "00000000-0000-4000-8000-000000000000"),
        params=params,
    )


class OutboundBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = OutboundBuilder()

    def test_trojan_reality_outbound(self) -> None:
        outbound = self.builder.build(
            server(
                "trojan",
                params={
                    "password": "secret",
                    "security": "reality",
                    "sni": "front.example",
                    "fp": "chrome",
                    "pbk": "public-key",
                    "sid": "abcd",
                },
            )
        )

        self.assertEqual(outbound["type"], "trojan")
        self.assertEqual(outbound["password"], "secret")
        self.assertEqual(outbound["tls"]["server_name"], "front.example")
        self.assertEqual(outbound["tls"]["utls"]["fingerprint"], "chrome")
        self.assertEqual(outbound["tls"]["reality"]["public_key"], "public-key")
        self.assertEqual(outbound["tls"]["reality"]["short_id"], "abcd")

    def test_vmess_rejects_reality(self) -> None:
        with self.assertRaises(OutboundBuildError):
            self.builder.build(server("vmess", params={"security": "reality", "pbk": "public-key"}))

    def test_hysteria2_obfs_requires_password(self) -> None:
        with self.assertRaises(OutboundBuildError):
            self.builder.build(server("hysteria2", params={"password": "secret", "obfs": "salamander"}))

    def test_hysteria2_obfs_and_bandwidth(self) -> None:
        outbound = self.builder.build(
            server(
                "hysteria2",
                params={
                    "password": "secret",
                    "obfs": "salamander",
                    "obfs-password": "obfs-secret",
                    "up_mbps": "50",
                    "down_mbps": "100",
                },
            )
        )

        self.assertEqual(outbound["type"], "hysteria2")
        self.assertEqual(outbound["obfs"], {"type": "salamander", "password": "obfs-secret"})
        self.assertEqual(outbound["up_mbps"], 50)
        self.assertEqual(outbound["down_mbps"], 100)

    def test_shadowsocks_2022_outbound(self) -> None:
        outbound = self.builder.build(
            server(
                "shadowsocks",
                port=8388,
                params={"method": "2022-blake3-aes-128-gcm", "password": "secret"},
            )
        )

        self.assertEqual(outbound["type"], "shadowsocks")
        self.assertEqual(outbound["method"], "2022-blake3-aes-128-gcm")
        self.assertEqual(outbound["password"], "secret")

    def test_wireguard_requires_keys_and_addresses(self) -> None:
        with self.assertRaises(OutboundBuildError):
            self.builder.build(server("wireguard", params={"private_key": "private"}))

        outbound = self.builder.build(
            server(
                "wireguard",
                port=51820,
                params={
                    "private_key": "private",
                    "peer_public_key": "peer",
                    "local_address": "172.16.0.2/32,fd00::2/128",
                    "reserved": "1,2,3",
                    "mtu": "1280",
                },
            )
        )

        self.assertEqual(outbound["type"], "wireguard")
        self.assertEqual(outbound["server_port"], 51820)
        self.assertEqual(outbound["local_address"], ["172.16.0.2/32", "fd00::2/128"])
        self.assertEqual(outbound["reserved"], [1, 2, 3])
        self.assertEqual(outbound["mtu"], 1280)


if __name__ == "__main__":
    unittest.main()
