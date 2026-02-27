use std::io::Write;
use std::path::{Path, PathBuf};
use std::fs;

/// Build the output file path: {base}/{dev_name}/{timestamp}/output.txt
/// Timestamp format: 2026-02-27T14-30-05 (filesystem-safe ISO-ish)
pub fn build_output_path(base: &str, dev_name: &str) -> Result<PathBuf, std::io::Error> {
    let now = jiff::Zoned::now();
    let ts = now.strftime("%Y-%m-%dT%H-%M-%S").to_string();
    let dir = Path::new(base).join(dev_name).join(&ts);
    fs::create_dir_all(&dir)?;
    Ok(dir.join("output.txt"))
}

/// Write output to a file, creating parent dirs as needed.
pub fn write_output(path: &Path, content: &str) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::File::create(path)?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_output_path_creates_dir_structure() {
        let tmp = std::env::temp_dir().join("sshinto_writer_test");
        let base = tmp.to_str().unwrap();

        let path = build_output_path(base, "router1").unwrap();

        // Path should end with output.txt
        assert_eq!(path.file_name().unwrap(), "output.txt");

        // Parent structure: base/router1/{timestamp}/output.txt
        let timestamp_dir = path.parent().unwrap();
        let device_dir = timestamp_dir.parent().unwrap();
        assert_eq!(device_dir.file_name().unwrap(), "router1");

        // Timestamp dir name should match YYYY-MM-DDTHH-MM-SS format
        let ts_name = timestamp_dir.file_name().unwrap().to_str().unwrap();
        assert_eq!(ts_name.len(), 19); // "2026-02-27T14-30-05"
        assert_eq!(&ts_name[4..5], "-");
        assert_eq!(&ts_name[7..8], "-");
        assert_eq!(&ts_name[10..11], "T");
        assert_eq!(&ts_name[13..14], "-");
        assert_eq!(&ts_name[16..17], "-");

        // Directory should exist
        assert!(timestamp_dir.is_dir());

        // Cleanup
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn write_output_creates_file() {
        let tmp = std::env::temp_dir().join("sshinto_writer_test2");
        let path = tmp.join("device").join("output.txt");

        write_output(&path, "hello world").unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "hello world");

        // Cleanup
        let _ = fs::remove_dir_all(&tmp);
    }
}
