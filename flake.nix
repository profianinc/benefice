{
  description = "Profian Benefice";

  inputs.cargo2nix.inputs.flake-compat.follows = "flake-compat";
  inputs.cargo2nix.inputs.flake-utils.follows = "flake-utils";
  inputs.cargo2nix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.cargo2nix.inputs.rust-overlay.follows = "rust-overlay";
  inputs.cargo2nix.url = github:cargo2nix/cargo2nix;
  inputs.enarx.inputs.flake-compat.follows = "flake-compat";
  inputs.enarx.inputs.flake-utils.follows = "flake-utils";
  inputs.enarx.inputs.nixpkgs.follows = "nixpkgs";
  inputs.enarx.url = github:enarx/enarx;
  inputs.flake-compat.flake = false;
  inputs.flake-compat.url = github:edolstra/flake-compat;
  inputs.flake-utils.url = github:numtide/flake-utils;
  inputs.nixpkgs.url = github:NixOS/nixpkgs;
  inputs.rust-overlay.inputs.flake-utils.follows = "flake-utils";
  inputs.rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  inputs.rust-overlay.url = github:oxalica/rust-overlay;

  outputs = {
    self,
    cargo2nix,
    enarx,
    flake-utils,
    nixpkgs,
    ...
  }:
    with flake-utils.lib.system;
      flake-utils.lib.eachSystem [
        aarch64-darwin
        aarch64-linux
        x86_64-darwin
        x86_64-linux
      ] (
        system: let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [cargo2nix.overlays.default];
          };
          pkgsX86_64LinuxMusl = import nixpkgs {
            inherit system;
            crossSystem = {
              config = "x86_64-unknown-linux-musl";
            };
            overlays = [cargo2nix.overlays.default];
          };

          devRust = pkgs.rust-bin.fromRustupToolchainFile "${self}/rust-toolchain.toml";
          devShell = pkgs.mkShell {
            buildInputs = [
              pkgs.openssl
              pkgs.cargo2nix

              devRust
              enarx.packages.${system}.enarx
            ];

            nativeBuildInputs = with pkgs; [
              pkg-config
            ];
          };

          cargo.toml = builtins.fromTOML (builtins.readFile "${self}/Cargo.toml");

          mkBin = args: pkgs:
            ((pkgs.rustBuilder.makePackageSet ({
                  packageFun = import "${self}/Cargo.nix";
                  rustVersion = "1.62.0";
                  workspaceSrc =
                    pkgs.nix-gitignore.gitignoreRecursiveSource [
                      "*.nix"
                      "*.yml"
                      "/.github"
                      "flake.lock"
                      "LICENSE"
                      "rust-toolchain.toml"
                    ]
                    self;
                }
                // args))
              .workspace
              ."${cargo.toml.package.name}" {})
            .bin;

          mkReleaseBin = mkBin {};

          nativeBin = mkReleaseBin pkgs;
          x86_64LinuxMuslBin = mkReleaseBin pkgsX86_64LinuxMusl;

          mkDebugBin = mkBin {release = false;};

          nativeDebugBin = mkDebugBin pkgs;
          x86_64LinuxMuslDebugBin = mkDebugBin pkgsX86_64LinuxMusl;

          buildImage = bin:
            pkgs.dockerTools.buildImage {
              inherit (cargo.toml.package) name;
              tag = cargo.toml.package.version;
              contents = [
                bin
              ];
              config.Cmd = [cargo.toml.package.name];
              config.Env = ["PATH=${bin}/bin"];
            };
        in {
          formatter = pkgs.alejandra;

          devShells.default = devShell;

          packages."${cargo.toml.package.name}" = nativeBin;
          packages."${cargo.toml.package.name}-x86_64-unknown-linux-musl" = x86_64LinuxMuslBin;
          packages."${cargo.toml.package.name}-x86_64-unknown-linux-musl-oci" = buildImage x86_64LinuxMuslBin;

          packages."${cargo.toml.package.name}-debug" = nativeDebugBin;
          packages."${cargo.toml.package.name}-debug-x86_64-unknown-linux-musl" = x86_64LinuxMuslDebugBin;
          packages."${cargo.toml.package.name}-debug-x86_64-unknown-linux-musl-oci" = buildImage x86_64LinuxMuslDebugBin;

          packages.default = nativeBin;
        }
      );
}
