use std::fs;

use flux::utils::directories::local_share_dir;
use silver_log::{
    counts::{LogName, counters_path, enable, names_path},
    error, info,
};

const ERROR_LINE: u32 = line!() + 7;

fn log_some() {
    for n in 0..3 {
        info!(n, "not counted");
    }
    for n in 0..3 {
        error!("boom {n}");
    }
}

#[test]
fn counts_errors_per_callsite() {
    let app = format!("silver-test-{}", std::process::id());
    enable(&app).unwrap();
    log_some();

    let counts: Vec<_> = fs::read(counters_path(&app))
        .unwrap()
        .chunks(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let names = LogName::read(&names_path(&app)).unwrap();
    fs::remove_dir_all(local_share_dir().join(&app)).unwrap();

    assert_eq!(counts.len(), names.len());
    let boom =
        names.iter().position(|n| (n.file.as_str(), n.line) == (file!(), ERROR_LINE)).unwrap();
    assert_eq!((names[boom].level.as_str(), names[boom].template.as_str()), ("ERROR", "boom {n}"));
    assert_eq!(counts[boom], 3);
    assert_eq!(counts.iter().sum::<u64>(), 3);
}
