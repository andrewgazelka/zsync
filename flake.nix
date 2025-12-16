{
  description = "zsync - Fast, modern file synchronization";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
          targets = [
            "x86_64-unknown-linux-gnu"
            "aarch64-unknown-linux-gnu"
            "x86_64-apple-darwin"
            "aarch64-apple-darwin"
          ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common args for all builds
        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
          buildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.CoreFoundation
            pkgs.darwin.apple_sdk.frameworks.CoreServices
          ];
        };

        # Build dependencies separately for better caching
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Main package
        zsync = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });

        # Agent-only package (for cross-compilation)
        zsync-agent = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          cargoExtraArgs = "-p zsync-agent";
        });

      in {
        packages = {
          default = zsync;
          inherit zsync zsync-agent;
        };

        devShells.default = craneLib.devShell {
          packages = with pkgs; [
            rust-analyzer
            cargo-watch
            cargo-nextest
          ];

          # For cross-compilation
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = "${pkgs.pkgsCross.gnu64.stdenv.cc}/bin/x86_64-unknown-linux-gnu-gcc";
          CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER = "${pkgs.pkgsCross.aarch64-multiplatform.stdenv.cc}/bin/aarch64-unknown-linux-gnu-gcc";
        };

        checks = {
          inherit zsync;
          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- -D warnings";
          });
          fmt = craneLib.cargoFmt { src = ./.; };
          nextest = craneLib.cargoNextest (commonArgs // {
            inherit cargoArtifacts;
            partitions = 1;
            partitionType = "count";
          });
        };
      }
    );
}
