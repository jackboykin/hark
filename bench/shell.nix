# Tooling for the hark throughput bench rig (bench/throughput/run.sh).
# Uses the ambient <nixpkgs> by default — fine for ad-hoc benching. For
# reproducible baselines, override `pkgs` with a pinned import or run via
# a flake that locks nixpkgs.
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  packages = with pkgs; [
    nsd
    dnsperf
    iproute2
    bind.dnsutils
    python3
    perf
    flamegraph
  ];
}
