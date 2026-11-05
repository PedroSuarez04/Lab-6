import unittest
from loopback_validator import is_loopback_address, parse_ip_address


class TestLoopbackAddressValidator(unittest.TestCase):

    # --- 1. Standard IPv4 127.0.0.1 ---
    def test_standard_ipv4_localhost(self):
        self.assertTrue(is_loopback_address("127.0.0.1"))
        self.assertTrue(
            is_loopback_address("127.0.0.1", allow_os_encodings=False)
        )

    # --- 2. Entire 127.0.0.0/8 IPv4 Subnet ---
    def test_other_127_slash_8_addresses(self):
        # RFC 1122 reserves the entire 127.0.0.0/8 block for loopback
        self.assertTrue(is_loopback_address("127.0.0.2"))
        self.assertTrue(is_loopback_address("127.1.2.3"))
        self.assertTrue(is_loopback_address("127.255.255.254"))
        self.assertTrue(is_loopback_address("127.255.255.255"))
        self.assertTrue(is_loopback_address("127.0.0.0"))

    # --- 3. IPv6 Loopback (::1) ---
    def test_ipv6_loopback(self):
        self.assertTrue(is_loopback_address("::1"))
        self.assertTrue(is_loopback_address("0:0:0:0:0:0:0:1"))
        self.assertTrue(
            is_loopback_address("0000:0000:0000:0000:0000:0000:0000:0001")
        )

    def test_ipv6_with_zone_identifier(self):
        # RFC 4007 Scoped IPv6 address (e.g., interface-specific loopback)
        self.assertTrue(is_loopback_address("::1%lo0"))
        self.assertTrue(is_loopback_address("::1%1"))

    # --- 4. IPv4-Mapped IPv6 ---
    def test_ipv4_mapped_ipv6(self):
        # Dual-stack mapped addresses targeting 127.0.0.0/8
        self.assertTrue(
            is_loopback_address(
                "::ffff:127.0.0.1", resolve_ipv4_mapped=True
            )
        )
        self.assertTrue(
            is_loopback_address(
                "::ffff:127.0.0.254", resolve_ipv4_mapped=True
            )
        )

        # In strict RFC 4291 mode (without IPv4 mapping resolution)
        self.assertFalse(
            is_loopback_address(
                "::ffff:127.0.0.1", resolve_ipv4_mapped=False
            )
        )

    # --- 5. Non-Loopback Addresses ---
    def test_non_loopback_addresses(self):
        # IPv4 non-loopback
        self.assertFalse(is_loopback_address("192.168.1.1"))
        self.assertFalse(is_loopback_address("10.0.0.1"))
        self.assertFalse(is_loopback_address("172.16.0.1"))
        self.assertFalse(is_loopback_address("8.8.8.8"))
        self.assertFalse(is_loopback_address("0.0.0.0"))
        self.assertFalse(is_loopback_address("128.0.0.1"))
        self.assertFalse(is_loopback_address("224.0.0.1"))  # Multicast

        # IPv6 non-loopback
        self.assertFalse(is_loopback_address("2001:db8::1"))
        self.assertFalse(is_loopback_address("fe80::1"))  # Link-local
        self.assertFalse(is_loopback_address("::"))  # Unspecified
        self.assertFalse(is_loopback_address("::2"))

        # IPv4-mapped non-loopback
        self.assertFalse(is_loopback_address("::ffff:192.168.1.1"))

    # --- 6. Alternate Text Encodings (OS / inet_aton accepted) ---
    def test_alternate_os_encodings_loopback(self):
        # Shorthand dotted notation
        self.assertTrue(
            is_loopback_address("127.1", allow_os_encodings=True)
        )  # 2-part (127.0.0.1)
        self.assertTrue(
            is_loopback_address("127.0.1", allow_os_encodings=True)
        )  # 3-part (127.0.0.1)

        # Octal notation
        self.assertTrue(
            is_loopback_address("0177.0.0.1", allow_os_encodings=True)
        )
        self.assertTrue(
            is_loopback_address("0177.0000.0000.0001", allow_os_encodings=True)
        )

        # Hexadecimal octets
        self.assertTrue(
            is_loopback_address("0x7f.0.0.1", allow_os_encodings=True)
        )
        self.assertTrue(
            is_loopback_address("0x7f.0x0.0x0.0x1", allow_os_encodings=True)
        )

        # 32-bit Integer / DWORD
        self.assertTrue(
            is_loopback_address("2130706433", allow_os_encodings=True)
        )  # 0x7F000001

        # Hexadecimal 32-bit integer
        self.assertTrue(
            is_loopback_address("0x7f000001", allow_os_encodings=True)
        )

    def test_alternate_os_encodings_non_loopback(self):
        # 010 (octal) = 8 in decimal -> 8.0.0.1 (public routable IP)
        self.assertFalse(
            is_loopback_address("010.0.0.1", allow_os_encodings=True)
        )

        # 10.1 (Class A shorthand) -> 10.0.0.1 (private non-loopback)
        self.assertFalse(
            is_loopback_address("10.1", allow_os_encodings=True)
        )

        # 0x0a000001 -> 10.0.0.1
        self.assertFalse(
            is_loopback_address("0x0a000001", allow_os_encodings=True)
        )

    # --- 7. Strict Mode Disallows Alternate Encodings ---
    def test_strict_mode_rejects_alternate_encodings(self):
        # When allow_os_encodings is False, strict RFC standard is enforced
        self.assertFalse(
            is_loopback_address("127.1", allow_os_encodings=False)
        )
        self.assertFalse(
            is_loopback_address("0177.0.0.1", allow_os_encodings=False)
        )
        self.assertFalse(
            is_loopback_address("0x7f000001", allow_os_encodings=False)
        )
        self.assertFalse(
            is_loopback_address("2130706433", allow_os_encodings=False)
        )

        # Strict parsing raises ValueError on non-standard formats
        with self.assertRaises(ValueError):
            parse_ip_address("0177.0.0.1", allow_os_encodings=False)

    # --- 8. Unsupported and Ambiguous Inputs ---
    def test_unsupported_inputs_raise_or_return_false(self):
        invalid_inputs = [
            "localhost",  # Hostname, not an IP literal
            "sub.localhost",  # Domain name
            "127.0.0.0/8",  # CIDR network range, not a host IP
            "127.0.0.1/32",  # Masked address
            "http://127.0.0.1",  # URL, not an IP
            "127.0.0.1:8080",  # IP with port
            "256.0.0.1",  # Octet out of bounds
            "::1::1",  # Malformed IPv6
            "not-an-ip",  # Garbage string
            "",  # Empty string
        ]

        for item in invalid_inputs:
            with self.subTest(item=item):
                # When raise_on_invalid is False, returns False
                self.assertFalse(
                    is_loopback_address(item, raise_on_invalid=False)
                )

                # When raise_on_invalid is True, explicitly raises ValueError
                with self.assertRaises(ValueError):
                    is_loopback_address(item, raise_on_invalid=True)


if __name__ == "__main__":
    unittest.main()
