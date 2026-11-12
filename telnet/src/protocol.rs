pub const IAC: u8 = 255;
pub const DONT: u8 = 254;
pub const DO: u8 = 253;
pub const WONT: u8 = 252;
pub const WILL: u8 = 251;
pub const SB: u8 = 250;
pub const SE: u8 = 240;

#[derive(Clone, Copy)]
enum State {
    Data,
    Iac,
    Option(u8),
    Sub,
    SubIac,
}

pub struct Parser {
    state: State,
}

impl Parser {
    pub fn new() -> Self {
        Parser { state: State::Data }
    }

    pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut data = Vec::new();
        let mut replies = Vec::new();

        for &b in input {
            self.state = match self.state {
                State::Data if b == IAC => State::Iac,
                State::Data => {
                    data.push(b);
                    State::Data
                }
                State::Iac => match b {
                    IAC => {
                        data.push(IAC);
                        State::Data
                    }
                    DO | DONT | WILL | WONT => State::Option(b),
                    SB => State::Sub,
                    _ => State::Data,
                },
                State::Option(cmd) => {
                    match cmd {
                        DO => replies.extend([IAC, WONT, b]),
                        WILL => replies.extend([IAC, DONT, b]),
                        _ => {}
                    }
                    State::Data
                }
                State::Sub if b == IAC => State::SubIac,
                State::Sub => State::Sub,
                State::SubIac if b == SE => State::Data,
                State::SubIac => State::Sub,
            };
        }

        (data, replies)
    }
}

pub fn escape(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        if b == IAC {
            out.push(IAC);
        }
        out.push(b);
    }
    out
}
