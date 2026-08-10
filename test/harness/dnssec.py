"""DNSSEC key material + signing utilities for the scripted authority harness.

`KeyMaterial.generate(zone_name)` produces a fresh ECDSA P-256 (RFC 6605,
algorithm 13) keypair plus a matching DNSKEY (ZSK; KSK semantics aren't
distinguished — one key signs everything) and a SHA-256 DS record. The
DS, exported via `ds_presentation()`, plugs into hark's test-only
`[resolver] trust-anchors = [...]` config.

Signatures are minted with generous time bounds (inception −1d,
expiration +1y) so the synthetic test clock never expires them mid-scenario.
Tests probing proof-lifetime behavior shrink the window via `sig_validity`.
"""

from __future__ import annotations

import dataclasses
import datetime

import dns.dnssec
import dns.name
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rdtypes.ANY.RRSIG
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec


# RFC 6605 §1: ECDSA P-256 / SHA-256.
_ALGO = dns.dnssec.Algorithm.ECDSAP256SHA256
# RFC 4509 §1: SHA-256 DS digest.
_DS_DIGEST = dns.dnssec.DSDigest.SHA256
# RFC 4034 §2.1.1: ZONE flag (bit 7). KSK (bit 15 = SEP) would let us
# split signing roles; harness doesn't need the distinction.
_DNSKEY_FLAGS = 256


@dataclasses.dataclass
class KeyMaterial:
    zone_name: dns.name.Name
    private_key: ec.EllipticCurvePrivateKey
    dnskey: dns.rdtypes.ANY.DNSKEY.DNSKEY
    ds: dns.rdtypes.ANY.DS.DS
    sig_validity: datetime.timedelta = datetime.timedelta(days=365)
    # Pre-signed `[DNSKEY rrset, RRSIG rrset]` answer for DNSKEY queries
    # against this zone. Built once at construction so DNSKEY synthesis
    # on the hot path is a list copy, not an ECDSA signature.
    signed_dnskey_response: tuple[dns.rrset.RRset, dns.rrset.RRset] = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        rrset = self.dnskey_rrset()
        self.signed_dnskey_response = (rrset, self.sign(rrset))

    def dnskey_rrset(self) -> dns.rrset.RRset:
        return dns.rrset.from_rdata(self.zone_name, 3600, self.dnskey)

    @classmethod
    def generate(cls, zone_name: str, sig_validity: datetime.timedelta | None = None) -> KeyMaterial:
        name = dns.name.from_text(zone_name)
        private_key = ec.generate_private_key(ec.SECP256R1())
        dnskey = dns.dnssec.make_dnskey(
            public_key=private_key.public_key(),
            algorithm=_ALGO,
            flags=_DNSKEY_FLAGS,
        )
        ds = dns.dnssec.make_ds(name=name, key=dnskey, algorithm=_DS_DIGEST)
        if sig_validity is None:
            sig_validity = cls.sig_validity
        return cls(zone_name=name, private_key=private_key, dnskey=dnskey, ds=ds, sig_validity=sig_validity)

    def sign(self, rrset: dns.rrset.RRset) -> dns.rrset.RRset:
        now = datetime.datetime.now(datetime.timezone.utc)
        rrsig = dns.dnssec.sign(
            rrset=rrset,
            private_key=self.private_key,
            signer=self.zone_name,
            dnskey=self.dnskey,
            inception=now - datetime.timedelta(days=1),
            expiration=now + self.sig_validity,
        )
        return dns.rrset.from_rdata(rrset.name, rrset.ttl, rrsig)

    def ds_presentation(self) -> str:
        """Format as hark's `trust-anchors` config string:
        `"<key-tag> <algorithm> <digest-type> <hex-digest>"`."""
        digest_hex = self.ds.digest.hex().upper()
        return f"{self.ds.key_tag} {int(self.ds.algorithm)} {int(self.ds.digest_type)} {digest_hex}"
