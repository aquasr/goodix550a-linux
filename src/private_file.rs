use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Create or truncate a sensitive output file.
///
/// On Unix, newly created files start with mode 0600 and an existing file is
/// explicitly narrowed to 0600 before any sensitive bytes are written.
pub(crate) fn open_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();

    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    options.mode(0o600);

    let file = options.open(path)?;

    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;

    Ok(file)
}

/// Write a complete sensitive artifact using the private-file policy.
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = open_private_file(path)?;

    file.write_all(bytes)?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn temporary_path(label: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        std::env::temp_dir().join(format!(
            "goodix-private-file-{label}-{}-{unique}",
            std::process::id()
        ))
    }

    #[test]
    fn private_writer_replaces_existing_contents() {
        let path = temporary_path("replace");

        fs::write(&path, b"old contents").unwrap();

        write_private_file(&path, b"new").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");

        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn new_private_file_has_mode_0600() {
        let path = temporary_path("new-mode");

        write_private_file(&path, b"sensitive").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;

        assert_eq!(mode, 0o600);

        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_permissive_file_is_narrowed_before_use() {
        let path = temporary_path("existing-mode");

        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );

        write_private_file(&path, b"sensitive").unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&path).unwrap(), b"sensitive");

        fs::remove_file(path).unwrap();
    }
}
