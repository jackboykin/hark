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
  packages = [ pyEnv ];
}
