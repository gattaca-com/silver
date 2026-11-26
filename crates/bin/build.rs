use std::env;

fn main() {
    let info = build_info_build::build_script().build();
    let git = info.version_control.as_ref().and_then(|vcs| vcs.git());
    let commit = env::var("SILVER_BUILD_COMMIT")
        .ok()
        .filter(|commit| !commit.is_empty())
        .or_else(|| git.map(|git| git.commit_short_id.clone()))
        .unwrap_or_else(|| "unknown".to_owned());
    let version_tag = format!("v{}", info.crate_info.version);
    let release = env::var("SILVER_RELEASE_TAG")
        .ok()
        .filter(|tag| !tag.is_empty())
        .or_else(|| {
            git.filter(|git| !git.dirty && git.tags.contains(&version_tag)).map(|_| version_tag)
        })
        .unwrap_or_default();
    println!("cargo:rerun-if-env-changed=SILVER_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=SILVER_RELEASE_TAG");
    println!("cargo:rustc-env=SILVER_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=SILVER_RELEASE_TAG={release}");
}
