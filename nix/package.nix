{
  lib,
  stdenv,
  zig_0_17,
  versionCheckHook,
}:

stdenv.mkDerivation {
  pname = "hark";
  version = lib.head (
    builtins.match ''.*\.version = "([^"]+)".*'' (builtins.readFile ../build.zig.zon)
  );

  src = lib.fileset.toSource {
    root = ./..;
    fileset = lib.fileset.unions [
      ../build.zig
      ../build.zig.zon
      ../src
      ../LICENSE
      ../systemd/hark.service
    ];
  };

  nativeBuildInputs = [ zig_0_17.hook ];
  strictDeps = true;

  doInstallCheck = true;
  nativeInstallCheckInputs = [ versionCheckHook ];

  meta = {
    description = "Validating, caching, recursive DNS resolver";
    homepage = "https://github.com/jackboykin/hark";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "hark";
  };
}
