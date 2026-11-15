use std::path::PathBuf;

use rsh_main::DEFAULT_PORT;

pub const USAGE: &str = "Usage:\n  rcp [-P port] <local-file> <host>:<remote-path>\n  rcp [-P port] <host>:<remote-path> <local-path>";

pub enum Location {
    Local(PathBuf),
    Remote { host: String, path: String },
}

pub struct Options {
    pub port: u16,
    pub source: Location,
    pub target: Location,
}

pub fn parse(args: &[String]) -> Result<Options, String> {
    let mut port = DEFAULT_PORT;
    let mut places = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-P" {
            let value = iter.next().ok_or("-P needs a port")?;
            port = value.parse().map_err(|_| format!("bad port: {value}"))?;
        } else {
            places.push(location(arg));
        }
    }

    if places.len() != 2 {
        return Err("need a source and a target".to_string());
    }
    let target = places.pop().unwrap();
    let source = places.pop().unwrap();
    Ok(Options {
        port,
        source,
        target,
    })
}

fn location(arg: &str) -> Location {
    if let Some((host, path)) = arg.split_once(':') {
        let is_drive = host.len() == 1;
        if !host.is_empty() && !is_drive && !host.contains(['/', '\\']) {
            return Location::Remote {
                host: host.to_string(),
                path: path.to_string(),
            };
        }
    }
    Location::Local(PathBuf::from(arg))
}
