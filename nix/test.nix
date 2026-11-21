self: {
  name = "hark";
  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.hark.enable = true;
    environment.systemPackages = [ pkgs.dnsutils ];
  };
  testScript = ''
    machine.wait_for_unit("hark.service")
    machine.wait_for_open_port(53, "127.0.0.1")
    machine.succeed("dig @127.0.0.1 localhost A +short | grep -Fx 127.0.0.1")
    machine.succeed("dig @::1 localhost AAAA +short | grep -Fx ::1")
  '';
}
