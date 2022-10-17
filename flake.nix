{
  description = "Profian Benefice";

  inputs.enarx.url = github:enarx/enarx;
  inputs.nixify.url = github:rvolosatovs/nixify;

  outputs = {
    enarx,
    nixify,
    ...
  }:
    with nixify.lib;
      rust.mkFlake {
        src = ./.;

        ignorePaths = [
          "/.github"
          "/.gitignore"
          "/Enarx.toml"
          "/flake.lock"
          "/flake.nix"
          "/LICENSE"
          "/rust-toolchain.toml"
        ];

        overlays = [
          enarx.overlays.rust
          enarx.overlays.default
        ];

        withDevShells = {
          devShells,
          pkgs,
          ...
        }:
          extendDerivations {
            buildInputs = [
              pkgs.enarx
            ];
          }
          devShells;
      };
}
