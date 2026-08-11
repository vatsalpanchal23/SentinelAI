"""
Target address policy.

Assessments cause this host to issue requests at whatever URL is
submitted, so an unvalidated target turns the app into an SSRF proxy: an
internal-only service, a container-network peer, or a cloud metadata
endpoint would all be fetched, and whatever comes back is stored in the
assessment's findings/report. Hostnames are resolved and every resulting
address is checked before an assessment is accepted.

Loopback/private targets are legitimate for local testing, so they are
allowed via ALLOW_PRIVATE_TARGETS=true. Link-local (including the
169.254.169.254 cloud metadata address), multicast, and reserved space
are never allowed -- there is no assessment use case for them.

A hostname that doesn't resolve is not treated as a policy violation: it
reaches nothing, so there is nothing to protect against, and the modules
will report the failure themselves. Note that this check runs at
submission time, so it does not close the DNS-rebinding window between
validation here and the requests the modules make later.
"""

import ipaddress
import socket
from urllib.parse import urlparse


def _addresses_for(hostname: str) -> set:
    literal = _as_ip(hostname)
    if literal is not None:
        return {literal}
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    return {ipaddress.ip_address(info[4][0]) for info in infos}


def _as_ip(hostname: str):
    try:
        return ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        return None


def _always_blocked(address) -> bool:
    return (
        address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def target_address_error(raw_url: str, allow_private: bool) -> str | None:
    """Returns an error message if `raw_url`'s host is not an allowed scan
    target, else None."""
    hostname = urlparse(raw_url).hostname
    if not hostname:
        return "Target URL must include a host (e.g. http://localhost:3000)."

    try:
        addresses = _addresses_for(hostname)
    except socket.gaierror:
        return None
    if not addresses:
        return None

    if any(_always_blocked(address) for address in addresses):
        return (
            f"Target '{hostname}' resolves into link-local/reserved address space "
            "(e.g. cloud metadata) and cannot be scanned."
        )

    if not allow_private and any(
        address.is_private or address.is_loopback for address in addresses
    ):
        return (
            f"Target '{hostname}' resolves to a private or loopback address. Set "
            "ALLOW_PRIVATE_TARGETS=true to allow scanning internal targets from "
            "this instance."
        )

    return None
