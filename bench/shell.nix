# Tooling for the hark throughput bench rig (bench/throughput/run.sh).
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
