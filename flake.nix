{
  description = "hark, a validating recursive resolver";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    zig = {
      url = "github:mitchellh/zig-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, zig }:
    let
      inherit (nixpkgs) lib;
      forAll = f: lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (s: f nixpkgs.legacyPackages.${s} zig.packages.${s});
      zigFor = z: z."master-2026-09-20";
      version = builtins.head (builtins.match ''.*\.version = "([^"]+)".*'' (builtins.readFile ./build.zig.zon));
    in
    {
      packages = forAll (pkgs: z: {
        default = pkgs.stdenv.mkDerivation {
          pname = "hark";
          version = "${version}+${self.shortRev or "dirty"}";
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [ ./build.zig ./build.zig.zon ./src ];
          };
          nativeBuildInputs = [ (zigFor z) ];
          installPhase = ''
            ZIG_GLOBAL_CACHE_DIR=$TMPDIR zig build -Doptimize=ReleaseSafe -Dcpu=baseline --prefix $out
          '';
          meta = {
            license = lib.licenses.mit;
            platforms = lib.platforms.linux;
            mainProgram = "hark";
          };
        };
      });

      devShells = forAll (pkgs: z: {
        default = pkgs.mkShell {
          packages = [
            (zigFor z)
            (pkgs.python3.withPackages (p: with p; [ dnspython cryptography pytest pytest-timeout pytest-xdist ]))
          ];
        };
        bench = pkgs.mkShell {
          packages = with pkgs; [
            (zigFor z)
            nsd dnsperf iproute2 util-linux bind.dnsutils shellcheck
            unbound pdns-recursor knot-resolver_6 bind
            (python3.withPackages (p: [ p.dnspython ]))
          ];
        };
      });
    };
}
