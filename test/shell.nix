# Tooling for the hark L4/L5 test suite (test/).
# Provides Python + dnspython + pytest for the scripted-authority harness.
# Run: cd test && nix-shell --run "pytest"
{ pkgs ? import <nixpkgs> {} }:

let
  pyEnv = pkgs.python3.withPackages (p: with p; [
    dnspython
    pytest
    pytest-xdist
  ]);
in
pkgs.mkShell {
  packages = [ pyEnv ];
}
