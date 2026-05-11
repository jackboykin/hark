"""Tests for the DNSSEC key-material + signing helpers."""

from __future__ import annotations

import re

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from . import dnssec as harness_dnssec


def test_keymaterial_round_trips_through_validate():
    """Generated DNSKEY + signature verifies via dnspython's own validator."""
    km = harness_dnssec.KeyMaterial.generate("example.com.")

    name = dns.name.from_text("example.com.")
    rrset = dns.rrset.from_text(name, 300, "IN", "A", "192.0.2.1", "192.0.2.2")
    rrsig_rrset = km.sign(rrset)

    dns.dnssec.validate_rrsig(
        rrset=rrset,
        rrsig=rrsig_rrset[0],
        keys={name: km.dnskey_rrset()},
    )  # raises on failure


def test_ds_matches_dnskey():
    """The generated DS is the SHA-256 of the DNSKEY rdata, per RFC 4034."""
    km = harness_dnssec.KeyMaterial.generate("example.com.")
    name = dns.name.from_text("example.com.")
    rederived = dns.dnssec.make_ds(name=name, key=km.dnskey, algorithm=dns.dnssec.DSDigest.SHA256)
    assert rederived.key_tag == km.ds.key_tag
    assert rederived.digest == km.ds.digest


def test_ds_presentation_matches_hark_config_format():
    """Output round-trips through hark's `<tag> <alg> <dtype> <hex>` shape."""
    km = harness_dnssec.KeyMaterial.generate("example.com.")
    s = km.ds_presentation()
    # 4 whitespace-separated fields; tag/alg/dtype are decimal; digest is hex.
    parts = s.split()
    assert len(parts) == 4
    tag, alg, dtype, digest_hex = parts
    assert tag.isdigit() and 0 <= int(tag) <= 65535
    assert alg.isdigit() and int(alg) == 13  # ECDSAP256SHA256
    assert dtype.isdigit() and int(dtype) == 2  # SHA-256
    assert re.fullmatch(r"[0-9A-F]+", digest_hex)
    assert len(digest_hex) == 64  # 32 bytes hex
