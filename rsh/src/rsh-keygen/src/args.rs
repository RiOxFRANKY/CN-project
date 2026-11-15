use std::path::PathBuf;

use rsh_main::paths;

pub const USAGE: &str = "Usage: rsh-keygen [-f keyfile] [-C comment] [-a]\n  -f  where to write the private key (public key gets .pub)\n  -C  comment stored in the public key\n  -a  also add the public key to this machine's authorized_keys";

pub struct Options {
    pub file: PathBuf,
    pub comment: String,
    pub authorize: bool,
}

pub fn parse(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        file: paths::identity(),
        comment: format!("{}@{}", paths::user_name(), paths::host_name()),
        authorize: false,
    };

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-f" => options.file = PathBuf::from(value(&mut iter, "-f")?),
            "-C" => options.comment = value(&mut iter, "-C")?.to_string(),
            "-a" => options.authorize = true,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown option: {other}")),
        }
    }
    Ok(options)
}

fn value<'a>(iter: &mut impl Iterator<Item = &'a String>, flag: &str) -> Result<&'a str, String> {
    iter.next()
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} needs a value"))
}
