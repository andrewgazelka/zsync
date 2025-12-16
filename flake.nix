{
  description = "zsync - Fast, modern file synchronization";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    crane,
  }: let
    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystems = f: nixpkgs.lib.genAttrs systems f;

    # Get pkgs for a system
    pkgsFor = system:
      import nixpkgs {
        inherit system;
        overlays = [rust-overlay.overlays.default];
      };

    # Rust toolchain (same for all systems)
    rustToolchainFor = pkgs:
      pkgs.rust-bin.stable.latest.default.override {
        extensions = ["rust-src" "rust-analyzer"];
      };

    # Crane lib for a system
    craneLibFor = system: let
      pkgs = pkgsFor system;
    in
      (crane.mkLib pkgs).overrideToolchain (rustToolchainFor pkgs);

    # Common build args for a system
    commonArgsFor = system: let
      pkgs = pkgsFor system;
      craneLib = craneLibFor system;
    in {
      src = craneLib.cleanCargoSource ./.;
      strictDeps = true;
      # Darwin frameworks (Security, CoreFoundation, CoreServices) are now
      # automatically included in the Darwin stdenv on nixpkgs-unstable
    };

    # Build zsync-agent for a system (native build, no embedded agents)
    agentFor = system: let
      craneLib = craneLibFor system;
      commonArgs = commonArgsFor system;
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;
    in
      craneLib.buildPackage (commonArgs
        // {
          inherit cargoArtifacts;
          cargoExtraArgs = "-p zsync-agent";
        });

    # Build zsync CLI (without embedded agents - for local dev/testing)
    zsyncFor = system: let
      craneLib = craneLibFor system;
      commonArgs = commonArgsFor system;
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;
    in
      craneLib.buildPackage (commonArgs
        // {
          inherit cargoArtifacts;
          cargoExtraArgs = "-p zsync";
        });

    # Variant with embedded agents (requires Linux agents available)
    zsyncWithAgentsFor = system: let
      pkgs = pkgsFor system;
      craneLib = craneLibFor system;
      commonArgs = commonArgsFor system;
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;
    in
      craneLib.buildPackage (commonArgs
        // {
          inherit cargoArtifacts;
          cargoExtraArgs = "-p zsync";
          ZSYNC_AGENT_LINUX_X86_64 = "${self.packages.x86_64-linux.zsync-agent}/bin/zsync-agent";
          ZSYNC_AGENT_LINUX_AARCH64 = "${self.packages.aarch64-linux.zsync-agent}/bin/zsync-agent";
        });
  in {
    packages = forAllSystems (system: let
      pkgs = pkgsFor system;
    in
      {
        default = zsyncFor system;
        zsync = zsyncFor system;
        zsync-agent = agentFor system;
      }
      // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
        # Only expose zsync-with-agents on Darwin
        zsync-with-agents = zsyncWithAgentsFor system;
      });

    devShells = forAllSystems (system: let
      pkgs = pkgsFor system;
      craneLib = craneLibFor system;
    in {
      default = craneLib.devShell {
        packages = [
          pkgs.rust-analyzer
          pkgs.cargo-watch
          pkgs.cargo-nextest
        ];
      };
    });

    checks = forAllSystems (system: let
      craneLib = craneLibFor system;
      commonArgs = commonArgsFor system;
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;
    in {
      zsync = self.packages.${system}.zsync;
      zsync-agent = self.packages.${system}.zsync-agent;
      clippy = craneLib.cargoClippy (commonArgs
        // {
          inherit cargoArtifacts;
          cargoClippyExtraArgs = "--all-targets -- -D warnings";
        });
      fmt = craneLib.cargoFmt {src = ./.;};
      nextest = craneLib.cargoNextest (commonArgs
        // {
          inherit cargoArtifacts;
          partitions = 1;
          partitionType = "count";
        });
    });
  };
}
