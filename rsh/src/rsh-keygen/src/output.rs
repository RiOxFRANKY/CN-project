use std::io::{self, BufRead, Write};
use std::path::Path;

use rsh_crypto::keyfile::public_path;
use rsh_crypto::KeyPair;

pub fn confirm_overwrite(path: &Path) -> io::Result<bool> {
    print!("{} already exists.\nOverwrite (y/n)? ", path.display());
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("y"))
}

pub fn report(path: &Path, pair: &KeyPair, comment: &str) {
    println!("Your identification has been saved in {}", path.display());
    println!(
        "Your public key has been saved in {}",
        public_path(path).display()
    );
    println!("The key fingerprint is:");
    println!("{} {comment}", pair.public.fingerprint());
    println!("Modulus n = {} (64-bit), e = {}", pair.public.n, pair.public.e);
}
