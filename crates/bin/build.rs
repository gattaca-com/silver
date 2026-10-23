use std::env;

fn main() {
    let info = build_info_build::build_script().build();
    let commit = env::var("SILVER_BUILD_COMMIT")
        .ok()
        .filter(|commit| !commit.is_empty())
        .or_else(|| {
            info.version_control
                .as_ref()
                .and_then(|vcs| vcs.git())
                .map(|git| git.commit_short_id.clone())
        })
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rerun-if-env-changed=SILVER_BUILD_COMMIT");
    println!("cargo:rustc-env=SILVER_BUILD_COMMIT={commit}");
}
