{
  description = "hark, a validating recursive resolver";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      forAll = f: lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (s: f nixpkgs.legacyPackages.${s});
    in
    {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.go_1_27 ];
        };
        bench = pkgs.mkShell {
          packages = with pkgs; [
            nsd dnsperf iproute2 util-linux bind.dnsutils shellcheck strace
            unbound pdns-recursor knot-resolver_6 bind
            python3 go_1_27
          ];
        };
      });
    };
}
