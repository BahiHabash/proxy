use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// A small size-bounded log writer for the tracing non-blocking worker.
///
/// Rotation is intentionally simple and predictable:
/// - current file: `<prefix>`
/// - rotated files: `<prefix>.1`, `<prefix>.2`, ...
/// - file count is capped by `max_files`
/// - logs are reset on day rollover and files older than one day are purged
pub struct SizeRotatingFile {
    dir: PathBuf,
    filename: String,
    max_bytes: u64,
    max_files: usize,
    file: Option<File>,
    current_size: u64,
    current_day: u64,
    day_provider: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl SizeRotatingFile {
    pub fn new(
        dir: impl AsRef<Path>,
        filename: impl Into<String>,
        max_bytes: u64,
        max_files: usize,
    ) -> io::Result<Self> {
        Self::new_with_day_provider(
            dir,
            filename,
            max_bytes,
            max_files,
            Arc::new(current_epoch_day),
        )
    }

    fn new_with_day_provider(
        dir: impl AsRef<Path>,
        filename: impl Into<String>,
        max_bytes: u64,
        max_files: usize,
        day_provider: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;

        let filename = filename.into();
        cleanup_expired_logs(&dir, &filename, ONE_DAY)?;
        let path = dir.join(&filename);
        let append_existing = !is_expired(&path, ONE_DAY);
        let file = OpenOptions::new()
            .create(true)
            .append(append_existing)
            .write(true)
            .truncate(!append_existing)
            .open(&path)?;
        let current_size = file.metadata()?.len();
        let current_day = day_provider();

        Ok(Self {
            dir,
            filename,
            max_bytes: max_bytes.max(1),
            max_files: max_files.max(1),
            file: Some(file),
            current_size,
            current_day,
            day_provider,
        })
    }

    fn current_path(&self) -> PathBuf {
        self.dir.join(&self.filename)
    }

    fn rotated_path(&self, index: usize) -> PathBuf {
        self.dir.join(format!("{}.{}", self.filename, index))
    }

    fn rotate(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }

        let oldest = self.rotated_path(self.max_files);
        if oldest.exists() {
            let _ = fs::remove_file(oldest);
        }

        for index in (1..self.max_files).rev() {
            let from = self.rotated_path(index);
            if from.exists() {
                let to = self.rotated_path(index + 1);
                let _ = fs::rename(from, to);
            }
        }

        let current = self.current_path();
        if current.exists() {
            let _ = fs::rename(&current, self.rotated_path(1));
        }

        self.file = Some(OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(current)?);
        self.current_size = 0;
        Ok(())
    }

    fn reset_for_new_day(&mut self, new_day: u64) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }

        remove_matching_logs(&self.dir, &self.filename)?;
        let current = self.current_path();
        self.file = Some(OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(current)?);
        self.current_size = 0;
        self.current_day = new_day;
        Ok(())
    }
}

impl Write for SizeRotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let day = (self.day_provider)();
        if day != self.current_day {
            self.reset_for_new_day(day)?;
        }

        if self.current_size > 0 && self.current_size + buf.len() as u64 > self.max_bytes {
            self.rotate()?;
        }

        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("log file is not open"))?;
        let written = file.write(buf)?;
        self.current_size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()
        } else {
            Ok(())
        }
    }
}

fn current_epoch_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / ONE_DAY.as_secs()
}

fn cleanup_expired_logs(dir: &Path, filename: &str, max_age: Duration) -> io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !is_log_file(name, filename) || !is_expired(&path, max_age) {
            continue;
        }
        let _ = fs::remove_file(path);
    }

    Ok(())
}

fn remove_matching_logs(dir: &Path, filename: &str) -> io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if is_log_file(name, filename) {
            let _ = fs::remove_file(path);
        }
    }

    Ok(())
}

fn is_log_file(name: &str, filename: &str) -> bool {
    name == filename || name.starts_with(&format!("{}.", filename))
}

fn is_expired(path: &Path, max_age: Duration) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    modified
        .elapsed()
        .map(|age| age >= max_age)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::SizeRotatingFile;
    use std::fs;
    use std::io::Write;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rotates_and_retains_bounded_files() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("proxy-log-test-{}", unique));

        let mut writer = SizeRotatingFile::new(&dir, "proxy.log", 32, 2).unwrap();
        for _ in 0..10 {
            writer.write_all(b"0123456789abcdef\n").unwrap();
        }
        writer.flush().unwrap();

        assert!(dir.join("proxy.log").exists());
        assert!(dir.join("proxy.log.1").exists());
        assert!(dir.join("proxy.log.2").exists());
        assert!(!dir.join("proxy.log.3").exists());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resets_logs_on_day_rollover() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("proxy-log-day-test-{}", unique));
        let day = Arc::new(AtomicU64::new(10));
        let day_for_writer = Arc::clone(&day);

        let mut writer = SizeRotatingFile::new_with_day_provider(
            &dir,
            "proxy.log",
            16,
            2,
            Arc::new(move || day_for_writer.load(Ordering::Relaxed)),
        )
        .unwrap();
        writer.write_all(b"0123456789abcdef\n").unwrap();
        writer.write_all(b"0123456789abcdef\n").unwrap();
        writer.flush().unwrap();
        assert!(dir.join("proxy.log.1").exists());

        day.store(11, Ordering::Relaxed);
        writer.write_all(b"new-day\n").unwrap();
        writer.flush().unwrap();

        assert!(dir.join("proxy.log").exists());
        assert!(!dir.join("proxy.log.1").exists());
        assert_eq!(fs::read_to_string(dir.join("proxy.log")).unwrap(), "new-day\n");

        let _ = fs::remove_dir_all(dir);
    }
}
