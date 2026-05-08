# Tooling for the hark recursion bench rig (bench/recursion/run.sh).
# Brings in everything dnsjit + shotgun's dnssim need to build natively, plus
# Python plotting deps. dnsjit isn't packaged in nixpkgs — run.sh builds it
# from source into .shotgun/, gated by these libs being available.
{ pkgs ? import <nixpkgs> {} }:

let
  pyEnv = pkgs.python3.withPackages (p: with p; [
    jinja2
    toml
    matplotlib
  ]);
in
pkgs.mkShell {
  packages = with pkgs; [
    # build deps for dnsjit (https://github.com/DNS-OARC/dnsjit)
    autoconf
    automake
    libtool
    pkg-config
    gcc
    libpcap
    libuv
    openssl
    gnutls
    ldns
    luajit
    libck           # ck.h / lock-free queues
    lmdb            # dnsjit input.lmdb backend
    zlib            # pcap compression
    lz4
    zstd

    # build deps for dnssim (shotgun/replay/dnssim)
    cmake
    ninja
    nghttp2
    ngtcp2-gnutls # QUIC with gnutls crypto (USE_SYSTEM_NGTCP2=ON)
    knot-dns      # provides libknot
    # libuv, openssl, gnutls already above

    # pellet preparation
    wireshark-cli # provides tshark + dumpcap
    bind.dnsutils # dig for smoke checks

    # shotgun driver + plotters
    pyEnv
    git
  ];

  shellHook = ''
    export SHOTGUN_DIR="$(realpath "''${BASH_SOURCE%/*}")/.shotgun"
    export PATH="$SHOTGUN_DIR:$PATH"
  '';
}
