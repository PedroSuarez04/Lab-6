from __future__ import annotations

import ipaddress
import socket


def parse_ip_address(
    address: str,
    *,
    allow_os_encodings: bool = True,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parses a string into an IPv4Address or IPv6Address object.

    Args:
        address: The string representation of an IP address.
        allow_os_encodings: If True, permits legacy OS C-library (inet_aton)
          formats for IPv4 (octal, hex, DWORD integers, and shorthand dotted
          notation). If False, strictly enforces RFC-compliant standard
          dotted-decimal and IPv6 formatting via `ipaddress`.

    Returns:
        An IPv4Address or IPv6Address instance.

    Raises:
        TypeError: If the input is not a string.
        ValueError: If the address cannot be parsed or represents an
          unsupported format (such as hostnames or CIDR prefixes).
    """
    if not isinstance(address, str):
        raise TypeError(
            f"Expected address as string, got {type(address).__name__}"
        )

    clean_addr = address.strip()
    if not clean_addr:
        raise ValueError("Address string cannot be empty.")

    # 1. Handle IPv6 Scope / Zone Identifiers (RFC 4007, e.g., '::1%lo0', 'fe80::1%eth0')
    if "%" in clean_addr:
        base_addr, _, _ = clean_addr.partition("%")
        try:
            ip = ipaddress.IPv6Address(base_addr)
            return ip
        except ValueError:
            pass  # Fall through to standard parsing if malformed

    # 2. Strict standard parsing (RFC 791 / RFC 4291 / RFC 5952)
    try:
        return ipaddress.ip_address(clean_addr)
    except ValueError as strict_err:
        strict_exception = strict_err

    # 3. Optional fallback: OS C-library (inet_aton) parser for legacy IPv4 encodings
    if allow_os_encodings:
        try:
            # socket.inet_aton accepts BSD formats:
            # - Dword / 32-bit integer: "2130706433"
            # - Hexadecimal: "0x7f.0.0.1", "0x7f000001"
            # - Octal octets: "0177.0.0.1"
            # - Shorthand: "127.1" (Class A, 24-bit host), "127.0.1" (Class B, 16-bit host)
            packed = socket.inet_aton(clean_addr)

            # Reject inputs that inet_aton incorrectly accepts on some platforms (e.g. whitespace)
            canonical_dotted = socket.inet_ntoa(packed)
            return ipaddress.IPv4Address(canonical_dotted)
        except (OSError, ValueError):
            pass

    raise ValueError(
        f"'{address}' is not a valid IP address: {strict_exception}"
    )


def is_loopback_address(
    address: str,
    *,
    allow_os_encodings: bool = True,
    resolve_ipv4_mapped: bool = True,
    raise_on_invalid: bool = False,
) -> bool:
    """Validates whether an IP address string is a loopback address.

    Args:
        address: The IP address string to validate.
        allow_os_encodings: If True, accepts legacy BSD/OS-accepted IPv4
          notations (e.g., '127.1', '0177.0.0.1', '0x7f000001').
        resolve_ipv4_mapped: If True, evaluates IPv4-mapped IPv6 addresses (e.g.,
          '::ffff:127.0.0.1') based on their mapped IPv4 target interface.
        raise_on_invalid: If True, raises ValueError when the string is not a
          parseable IP address. If False, returns False for invalid strings.

    Returns:
        bool: True if the address evaluates to a loopback address, False
        otherwise.
    """
    try:
        ip = parse_ip_address(address, allow_os_encodings=allow_os_encodings)
    except (ValueError, TypeError):
        if raise_on_invalid:
            raise
        return False

    # Check IPv4 loopback (127.0.0.0/8 per RFC 1122)
    if ip.version == 4:
        return ip.is_loopback

    # Check IPv6 loopback and IPv4-mapped IPv6 addresses
    if ip.version == 6:
        # Handle mapped IPv4 addresses before checking IPv6 loopback
        if ip.ipv4_mapped is not None:
            if resolve_ipv4_mapped:
                return ip.ipv4_mapped.is_loopback
            return False

        if ip.is_loopback:
            return True

    return False
