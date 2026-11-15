use std::collections::VecDeque;

pub struct EchoFilter {
    expected: VecDeque<u8>,
    held: Vec<u8>,
}

impl EchoFilter {
    pub fn new() -> Self {
        EchoFilter {
            expected: VecDeque::new(),
            held: Vec::new(),
        }
    }

    pub fn expect(&mut self, input: &[u8]) {
        if !cfg!(windows) {
            return;
        }
        for line in input.split_inclusive(|&b| b == b'\n') {
            if line.last() != Some(&b'\n') {
                continue;
            }
            let text = line.strip_suffix(b"\n").unwrap_or(line);
            let text = text.strip_suffix(b"\r").unwrap_or(text);
            self.expected.extend(text);
            self.expected.extend(b"\r\n");
        }
    }

    pub fn filter(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &b in data {
            match self.expected.front() {
                Some(&e) if e == b => {
                    self.expected.pop_front();
                    self.held.push(b);
                    if b == b'\n' {
                        self.held.clear();
                    }
                }
                Some(_) => {
                    self.expected.clear();
                    out.append(&mut self.held);
                    out.push(b);
                }
                None => out.push(b),
            }
        }
        out
    }

    pub fn flush(&mut self) -> Vec<u8> {
        self.expected.clear();
        std::mem::take(&mut self.held)
    }
}
