# Tooling for the hark L4/L5 test suite (test/).
# Provides Python + dnspython + pytest for the scripted-authority harness.
# Run: cd test && nix-shell --run "pytest"
{ pkgs ? import <nixpkgs> {} }:

let
  pyEnv = pkgs.python3.withPackages (p: with p; [
    dnspython
    # dnspython.dnssec.sign / verify call into `cryptography` lazily; without
    # it, signed scenarios silently can't run. Required by the DNSSEC harness
    # (test/harness/dnssec.py).
    cryptography
    pytest
    pytest-timeout
    pytest-xdist
  ]);
in
pkgs.mkShell {
  # `unbound` is the oracle for differential tests (run with `pytest -m differential`).
  # Note: the differential suite assumes Unbound ≥ 1.24.0, which shipped the
  # TTL=0 caching fix (NLnetLabs/unbound#1337, 2025-09). Older Unbounds cached
  # TTL=0 records by default, which would invalidate the test's premise about
  # the cache-min-ttl divergence being the surviving cheeky bit.
  packages = [ pyEnv pkgs.unbound ];
}
