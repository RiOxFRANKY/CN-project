use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn display(path: &Path) -> String {
    let text = path.display().to_string();
    match text.strip_prefix(r"\\?\") {
        Some(stripped) => stripped.to_string(),
        None => text,
    }
}

fn resolve(cwd: &Path, path: &str) -> PathBuf {
    if path.is_empty() {
        cwd.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn plain_name(name: &str) -> io::Result<&str> {
    match Path::new(name).file_name() {
        Some(base) if base == name => Ok(name),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("bad file name: {name}"),
        )),
    }
}

pub fn upload(cwd: &Path, path: &str, name: &str, data: &[u8]) -> io::Result<String> {
    let mut target = resolve(cwd, path);
    if target.is_dir() {
        target = target.join(plain_name(name)?);
    }
    fs::write(&target, data)?;
    Ok(format!("wrote {} bytes to {}", data.len(), display(&target)))
}

pub fn download(cwd: &Path, path: &str) -> io::Result<(String, Vec<u8>)> {
    let target = resolve(cwd, path);
    if target.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{path}: is a directory"),
        ));
    }
    let data = fs::read(&target).map_err(|e| io::Error::new(e.kind(), format!("{path}: {e}")))?;
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    Ok((name, data))
}
