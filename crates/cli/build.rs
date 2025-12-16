fn main() {
    // Register expected cfg flags for check-cfg
    println!("cargo::rustc-check-cfg=cfg(zsync_embed_linux_x86_64)");
    println!("cargo::rustc-check-cfg=cfg(zsync_embed_linux_aarch64)");

    // Agent paths are set by Nix during the build
    // These get passed to rustc and can be used with env!() / option_env!()
    let agents = [
        ("ZSYNC_AGENT_LINUX_X86_64", "zsync_embed_linux_x86_64"),
        ("ZSYNC_AGENT_LINUX_AARCH64", "zsync_embed_linux_aarch64"),
    ];

    for (env_var, cfg_flag) in agents {
        println!("cargo:rerun-if-env-changed={env_var}");
        if std::env::var(env_var).is_ok() {
            println!("cargo:rustc-cfg={cfg_flag}");
        }
    }
}
