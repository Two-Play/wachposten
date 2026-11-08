//! Access to the user's crontab. The spool belongs to root, so it is read and written through
//! the `crontab` command.

use std::io::{self, Write};
use std::process::{Command, Stdio};

pub trait CrontabBackend: Send {
    /// The current crontab, or `None` if the user has none.
    fn read(&self) -> io::Result<Option<Vec<u8>>>;
    /// Replace the crontab. `None` removes it.
    fn write(&self, content: Option<&[u8]>) -> io::Result<()>;
}

/// Uses the system `crontab` command.
pub struct SystemCrontab;

impl CrontabBackend for SystemCrontab {
    fn read(&self) -> io::Result<Option<Vec<u8>>> {
        let out = match Command::new("crontab")
            .arg("-l")
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(o) => o,
            // No cron installed: nothing to watch.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if out.status.success() {
            return Ok(Some(out.stdout));
        }
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("no crontab") {
            Ok(None)
        } else {
            Err(io::Error::other(format!("crontab -l: {}", err.trim())))
        }
    }

    fn write(&self, content: Option<&[u8]>) -> io::Result<()> {
        let status = match content {
            None => Command::new("crontab").arg("-r").status()?,
            Some(data) => {
                let mut child = Command::new("crontab")
                    .arg("-")
                    .stdin(Stdio::piped())
                    .spawn()?;
                child
                    .stdin
                    .take()
                    .ok_or_else(|| io::Error::other("no stdin"))?
                    .write_all(data)?;
                child.wait()?
            }
        };
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("crontab exited with {status}")))
        }
    }
}

/// Crontab watching switched off.
pub struct NoCrontab;

impl CrontabBackend for NoCrontab {
    fn read(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn write(&self, _content: Option<&[u8]>) -> io::Result<()> {
        Err(io::Error::other("crontab watching is disabled"))
    }
}

/// In-memory crontab for tests.
#[derive(Default)]
pub struct MemoryCrontab(pub std::sync::Mutex<Option<Vec<u8>>>);

impl CrontabBackend for MemoryCrontab {
    fn read(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn write(&self, content: Option<&[u8]>) -> io::Result<()> {
        *self.0.lock().unwrap() = content.map(<[u8]>::to_vec);
        Ok(())
    }
}

impl<T: CrontabBackend + Sync> CrontabBackend for std::sync::Arc<T> {
    fn read(&self) -> io::Result<Option<Vec<u8>>> {
        (**self).read()
    }
    fn write(&self, content: Option<&[u8]>) -> io::Result<()> {
        (**self).write(content)
    }
}
