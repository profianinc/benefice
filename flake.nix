{
  description = "Profian Benefice";

  inputs.crane.inputs.flake-compat.follows = "flake-compat";
  inputs.crane.inputs.flake-utils.follows = "flake-utils";
  inputs.crane.inputs.nixpkgs.follows = "nixpkgs";
  inputs.crane.url = github:ipetkov/crane;
  inputs.enarx.inputs.fenix.follows = "fenix";
  inputs.enarx.inputs.flake-compat.follows = "flake-compat";
  inputs.enarx.inputs.flake-utils.follows = "flake-utils";
  inputs.enarx.url = github:enarx/enarx;
  inputs.fenix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.fenix.url = github:nix-community/fenix;
  inputs.flake-compat.flake = false;
  inputs.flake-compat.url = github:edolstra/flake-compat;
  inputs.flake-utils.url = github:numtide/flake-utils;
  inputs.nixpkgs.url = github:NixOS/nixpkgs;
  inputs.rust-overlay.inputs.flake-utils.follows = "flake-utils";
  inputs.rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  inputs.rust-overlay.url = github:oxalica/rust-overlay;

  outputs = {
    self,
    crane,
    enarx,
    fenix,
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
            overlays = [
              # TODO: Add Enarx overlay
              fenix.overlay
            ];
          };

          rust = fenix.packages.${system}.fromToolchainFile {
            file = "${self}/rust-toolchain.toml";
            sha256 = "sha256-Et8XFyXhlf5OyVqJkxrmkxv44NRN54uU2CLUTZKUjtM=";
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain rust;

          mkBin = {
            CARGO_BUILD_RUSTFLAGS ? null,
            CARGO_BUILD_TARGET ? null,
            CARGO_PROFILE ? null,
          } @ args:
            craneLib.buildPackage ({
                src =
                  pkgs.nix-gitignore.gitignoreRecursiveSource [
                    "*.lock"
                    "!Cargo.lock"

                    "*.toml"
                    "!Cargo.toml"

                    "*.md"
                    "*.nix"
                    "/.github"
                    "LICENSE"
                  ]
                  self;

                buildInputs = with pkgs; [
                  openssl
                ];

                nativeBuildInputs = with pkgs; [
                  pkg-config
                ];
              }
              // (pkgs.lib.filterAttrs (n: v: v != null) args));

          nativeBin = mkBin {};
          x86_64LinuxMuslBin = mkBin {
            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
          };

          nativeDebugBin = mkBin {
            CARGO_PROFILE = "";
          };
          x86_64LinuxMuslDebugBin = mkBin {
            CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            CARGO_PROFILE = "";
          };

          cargo.toml = builtins.fromTOML (builtins.readFile "${self}/Cargo.toml");

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

          devShell = pkgs.mkShell {
            buildInputs = [
              pkgs.openssl

              rust
              enarx.packages.${system}.enarx
            ];

            nativeBuildInputs = with pkgs; [
              pkg-config
            ];
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
