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

    # Rust toolchain with musl targets for cross-compilation
    rustToolchainFor = pkgs:
      pkgs.rust-bin.stable.latest.default.override {
        extensions = ["rust-src" "rust-analyzer"];
        targets = ["x86_64-unknown-linux-musl" "aarch64-unknown-linux-musl"];
      };

    # Crane lib for a system (function form to avoid warnings)
    craneLibFor = system: let
      pkgs = pkgsFor system;
    in
      (crane.mkLib pkgs).overrideToolchain (p: rustToolchainFor p);

    # Common build args for a system
    commonArgsFor = system: let
      craneLib = craneLibFor system;
    in {
      src = craneLib.cleanCargoSource ./.;
      strictDeps = true;
    };

    # Build zsync-agent for a system (native build)
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

    # Cross-compile zsync-agent for Linux (static musl) from any host
    crossAgentFor = hostSystem: targetArch: let
      crossSystem =
        if targetArch == "x86_64"
        then "x86_64-unknown-linux-musl"
        else "aarch64-unknown-linux-musl";

      # Import nixpkgs with cross-compilation support and rust-overlay
      # This properly splices packages so the function form works
      pkgs = import nixpkgs {
        localSystem = hostSystem;
        inherit crossSystem;
        overlays = [rust-overlay.overlays.default];
      };

      cargoTarget = crossSystem;

      # Function form works because pkgs has rust-overlay applied
      craneLib = (crane.mkLib pkgs).overrideToolchain (p:
        p.rust-bin.stable.latest.default.override {
          targets = [crossSystem];
        }
      );

      commonArgs = {
        src = craneLib.cleanCargoSource ./.;
        strictDeps = true;
        CARGO_BUILD_TARGET = cargoTarget;
      };

      cargoArtifacts = craneLib.buildDepsOnly commonArgs;
    in
      craneLib.buildPackage (commonArgs
        // {
          inherit cargoArtifacts;
          cargoExtraArgs = "-p zsync-agent";
        });

    # Build zsync CLI with embedded Linux agents (cross-compiled static musl)
    zsyncWithAgentsFor = system: let
      pkgs = pkgsFor system;
      craneLib = craneLibFor system;
      commonArgs = commonArgsFor system;
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;

      # Cross-compile Linux agents
      linuxAgentX86 = crossAgentFor system "x86_64";
      linuxAgentArm = crossAgentFor system "aarch64";
    in
      craneLib.buildPackage (commonArgs
        // {
          inherit cargoArtifacts;
          cargoExtraArgs = "-p zsync";
          ZSYNC_AGENT_LINUX_X86_64 = "${linuxAgentX86}/bin/zsync-agent";
          ZSYNC_AGENT_LINUX_AARCH64 = "${linuxAgentArm}/bin/zsync-agent";
        });

    # Build zsync CLI without embedded agents (for quick local builds)
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
  in {
    packages = forAllSystems (system: let
      pkgs = pkgsFor system;
    in
      {
        # Default includes embedded agents (cross-compiled)
        default = zsyncWithAgentsFor system;
        zsync = zsyncWithAgentsFor system;
        zsync-agent = agentFor system;
        # Quick build without agents
        zsync-lite = zsyncFor system;
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
