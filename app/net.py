"""Where a request really came from, and whether that place is allowed.

Behind Apache the socket is always opened by the proxy, so ``request.client``
alone says ``127.0.0.1`` for every device on earth. The real address is in
``X-Forwarded-For`` — a header any client can write for itself.

The whole security value of this module rests on one rule: **X-Forwarded-For
is evidence only when the machine that opened the socket is a proxy we
trust.** If an arbitrary host on the internet connects to us directly, its
headers are its own invention and must be ignored outright; believing them
would let anyone claim any source address and walk straight through a
per-device CIDR allowlist.
"""

import ipaddress
import logging

from app import config

log = logging.getLogger(__name__)

_IP_TYPES = (ipaddress.IPv4Address, ipaddress.IPv6Address)


def parse_ip(value):
    """Best-effort address parse. Returns an ip_address, or None — never raises.

    Copes with the shapes proxies actually emit: surrounding whitespace, a
    bracketed IPv6 host with a port (``[2001:db8::1]:443``), an IPv4 host with
    a port (``203.0.113.5:9000``), and IPv4-mapped IPv6 (``::ffff:203.0.113.5``),
    which is folded down to plain IPv4 so that an operator's ``203.0.113.0/24``
    rule matches it as they would expect.
    """
    if not isinstance(value, str):
        return value if isinstance(value, _IP_TYPES) else None

    text = value.strip()
    if not text:
        return None

    if text.startswith("["):
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        # A single colon can only be an IPv4 host:port pair — an IPv6 address
        # always has at least two.
        text = text.split(":", 1)[0]

    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def _entries(cidrs):
    """Normalise a comma/whitespace separated string, or an iterable, to a list."""
    if cidrs is None:
        return []
    if isinstance(cidrs, str):
        raw = cidrs.replace("\n", ",").replace(";", ",").split(",")
    else:
        raw = list(cidrs)
    return [str(item).strip() for item in raw if str(item).strip()]


def parse_network(entry):
    """One allowlist entry → a network, or None. A bare address means /32 (/128)."""
    text = str(entry).strip()
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        pass
    # ::ffff:1.2.3.4 style entries: fold to IPv4 so they match folded addresses.
    addr = parse_ip(text)
    if addr is None:
        return None
    try:
        return ipaddress.ip_network(str(addr), strict=False)
    except ValueError:
        return None


def ip_in_cidrs(ip, cidrs) -> bool:
    """True when ``ip`` falls inside any entry of ``cidrs``.

    A malformed entry is logged and skipped: a typo must narrow access, never
    widen it. An empty or unparseable list therefore matches nothing at all,
    which is why enabling the per-device IP check with an empty allowlist is
    rejected at the API rather than silently locking a device out here.
    """
    addr = parse_ip(ip)
    if addr is None:
        return False

    for entry in _entries(cidrs):
        network = parse_network(entry)
        if network is None:
            log.warning("ignoring malformed allowlist entry %r", entry)
            continue
        try:
            if addr in network:
                return True
        except TypeError:
            continue  # an IPv4 address against an IPv6 network, or the reverse
    return False


def valid_cidrs(cidrs):
    """Split an allowlist into (accepted entries, rejected entries)."""
    good, bad = [], []
    for entry in _entries(cidrs):
        (good if parse_network(entry) is not None else bad).append(entry)
    return good, bad


def is_trusted_proxy(value) -> bool:
    """Is this address one of ours? TRUSTED_PROXIES may hold addresses or CIDRs."""
    return ip_in_cidrs(value, config.TRUSTED_PROXIES)


def client_ip(request) -> str:
    """The address to hold the caller of this request accountable for.

    * Immediate peer **not** trusted → the peer *is* the client. Any
      X-Forwarded-For it sent is self-asserted and is ignored completely.
    * Immediate peer trusted → walk the chain right to left and return the
      first address that is not itself a trusted proxy. That is the last hop
      one of our own proxies observed; everything further left was supplied by
      the client and is worthless.

    An unparseable hop stops the walk — a chain we cannot read is a chain we
    cannot trust, so we fall back to the peer rather than reading past it into
    client-controlled text.
    """
    peer = request.client.host if request.client else None
    peer_addr = parse_ip(peer)
    if peer_addr is None:
        return str(peer or "")

    if not is_trusted_proxy(peer_addr):
        return str(peer_addr)

    for hop in reversed(request.headers.get("x-forwarded-for", "").split(",")):
        if not hop.strip():
            continue
        addr = parse_ip(hop)
        if addr is None:
            log.warning("unreadable X-Forwarded-For hop %r — using the peer address", hop)
            break
        if is_trusted_proxy(addr):
            continue
        return str(addr)

    return str(peer_addr)
