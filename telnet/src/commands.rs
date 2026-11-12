use std::time::{SystemTime, UNIX_EPOCH};

pub fn execute(input: &str) -> Option<String> {
    let (cmd, arg) = match input.split_once(' ') {
        Some((c, a)) => (c, a.trim()),
        None => (input, ""),
    };

    let reply = match cmd.to_lowercase().as_str() {
        "" => String::new(),
        "help" => "Commands: help, echo <text>, time, quit".to_string(),
        "echo" => arg.to_string(),
        "time" => {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format!("Seconds since Unix epoch: {secs}")
        }
        "quit" | "exit" => return None,
        other => format!("Unknown command: {other}"),
    };

    Some(reply)
}
