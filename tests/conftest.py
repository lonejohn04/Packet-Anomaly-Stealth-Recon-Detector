"""Shared deterministic Scapy packet and PCAP fixtures for NetGuard tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from netguard.sample_generator import generate_all_samples

BASE_TS = 1700000000.0


def make_tcp_pkt(
    src_ip: str = "10.0.0.50",
    dst_ip: str = "10.0.0.10",
    sport: int = 50000,
    dport: int = 80,
    flags: str | int = "S",
    ts: float = BASE_TS,
    src_mac: str = "aa:bb:cc:dd:ee:01",
    dst_mac: str = "aa:bb:cc:dd:ee:02",
    ipv6: bool = False,
) -> Any:
    """Build a deterministic Ethernet/IP(v6)/TCP packet with explicit timestamp."""
    ip_layer = IPv6(src=src_ip, dst=dst_ip) if ipv6 else IP(src=src_ip, dst=dst_ip)
    pkt = Ether(src=src_mac, dst=dst_mac) / ip_layer / TCP(sport=sport, dport=dport, flags=flags)
    pkt.time = ts
    return pkt


def make_dns_pkt(
    qname: str | bytes = "www.example.com",
    qtype: str | int = "A",
    qr: int = 0,
    src_ip: str = "10.0.0.25",
    dst_ip: str = "10.0.0.2",
    ts: float = BASE_TS,
    over_tcp: bool = False,
    ipv6: bool = False,
) -> Any:
    """Build a deterministic DNS packet over UDP/TCP and IPv4/IPv6."""
    ip_layer = IPv6(src=src_ip, dst=dst_ip) if ipv6 else IP(src=src_ip, dst=dst_ip)
    l4 = TCP(sport=53000, dport=53, flags="PA") if over_tcp else UDP(sport=53000, dport=53)
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:25", dst="aa:bb:cc:dd:ee:02")
        / ip_layer
        / l4
        / DNS(qr=qr, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    )
    pkt.time = ts
    return pkt


def make_arp_pkt(
    op: int = 2,
    psrc: str = "192.168.1.1",
    pdst: str = "192.168.1.10",
    hwsrc: str = "aa:bb:cc:00:00:01",
    hwdst: str = "ff:ff:ff:ff:ff:ff",
    eth_src: str | None = None,
    eth_dst: str = "ff:ff:ff:ff:ff:ff",
    ts: float = BASE_TS,
) -> Any:
    """Build a deterministic Ethernet/ARP packet."""
    actual_eth_src = eth_src if eth_src is not None else hwsrc
    pkt = Ether(src=actual_eth_src, dst=eth_dst) / ARP(
        op=op, psrc=psrc, pdst=pdst, hwsrc=hwsrc, hwdst=hwdst
    )
    pkt.time = ts
    return pkt


@pytest.fixture(scope="session")
def generated_samples_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Generate deterministic sample PCAP files into an isolated session temp dir."""
    out = tmp_path_factory.mktemp("samples")
    generate_all_samples(out)
    return out
