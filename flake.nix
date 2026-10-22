{
  description = "hark, a validating recursive resolver";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      forAll = f: lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (s: f nixpkgs.legacyPackages.${s});
    in
    {
      # The bench's readers of its own output, bench/bench.cr.
      packages = forAll (pkgs: {
        bench = pkgs.crystal.buildCrystalPackage {
          pname = "bench";
          version = "0";
          src = lib.fileset.toSource {
            root = ./bench;
            fileset = lib.fileset.fileFilter (f: f.hasExt "cr") ./bench;
          };
          format = "crystal";
          crystalBinaries.bench.src = "bench.cr";
        };
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.zig_0_17 pkgs.go_1_27 ];
        };
        bench = pkgs.mkShell {
          packages = with pkgs; [
            nsd dnsperf iproute2 util-linux bind.dnsutils shellcheck strace
            unbound pdns-recursor knot-resolver_6 bind
            go_1_27 zig_0_17
            self.packages.${pkgs.stdenv.hostPlatform.system}.bench
          ];
        };
      });
    };
}
