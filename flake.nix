{
  description = "hark, a validating recursive resolver";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      forAll = f: lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (s: f nixpkgs.legacyPackages.${s});
    in
    {
      packages = forAll (pkgs: {
        default = pkgs.callPackage ./nix/package.nix { };
      });

      nixosModules.default = import ./nix/module.nix self;

      checks = forAll (pkgs: {
        nixos = pkgs.testers.runNixOSTest (import ./nix/test.nix self);
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.zig_0_17 pkgs.go_1_27 ];
        };
        bench = pkgs.mkShell {
          packages = with pkgs; [
            nsd iproute2 bind.dnsutils shellcheck strace
            unbound pdns-recursor knot-resolver_6 bind
            go_1_27 zig_0_17
          ];
        };
      });
    };
}
