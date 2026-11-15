use std::time::Instant;

pub fn done(name: &str, bytes: usize, start: Instant) {
    let secs = start.elapsed().as_secs_f64();
    let rate = if secs > 0.0 {
        bytes as f64 / 1024.0 / secs
    } else {
        0.0
    };
    println!("{name:<30} 100% {:>10} bytes {rate:>9.1} KB/s {secs:>6.2}s", bytes);
}
