self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.hark;
  toml = pkgs.formats.toml { };
  configFile = pkgs.runCommandLocal "hark.toml" { } ''
    cp ${toml.generate "hark.toml" cfg.settings} $out
    ${lib.optionalString (pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform) "${lib.getExe cfg.package} check --config $out"}
  '';
in
{
  options.services.hark = {
    enable = lib.mkEnableOption "hark, a validating recursive DNS resolver";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "hark.packages.\${pkgs.stdenv.hostPlatform.system}.default";
      description = "The hark package to run.";
    };
    settings = lib.mkOption {
      inherit (toml) type;
      default = { };
      example = {
        server.listen = [ "[::1]:5335" ];
        cache.size = 33554432;
      };
      description = ''
        hark.toml as Nix values. Its keys and their defaults are in
        hark.toml.example; hark refuses any other.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.packages = [ cfg.package ];
    systemd.services.hark = {
      wantedBy = [ "multi-user.target" ];
      stopIfChanged = false;
      # The empty entry clears the unit's own ExecStart.
      serviceConfig.ExecStart = [
        ""
        "${lib.getExe cfg.package} serve --config ${configFile}"
      ];
    };
  };
}
