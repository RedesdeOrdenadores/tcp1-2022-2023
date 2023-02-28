use regex::Regex;
use std::array::TryFromSliceError;
use std::num::ParseIntError;
use std::{fmt::Display, str::FromStr};
use thiserror::Error;
use tlv::TlvType;

mod tlv;

pub use tlv::Tlv;
pub use tlv::TlvIterator;

#[derive(Clone, Error, Debug)]
pub enum TCPLibError {
    #[error("Unsupported operation {0}")]
    UnsupportedOperation(String),
    #[error("Could not parse operation")]
    Parse,
    #[error("Not enough data in TLV")]
    NotEnoughData(#[from] TryFromSliceError),
    #[error("Could not parse integer")]
    ParseIntError(#[from] ParseIntError),
    #[error("Something wrong")]
    Generic,
}

#[derive(Debug)]
pub struct Answer {
    pub num: i64,
}

impl<'a> TryFrom<Tlv<'a>> for Answer {
    type Error = TCPLibError;

    fn try_from(tlv: Tlv) -> Result<Self, Self::Error> {
        if tlv.tag == TlvType::Numi64 && tlv.length == 8 {
            Ok(Answer {
                num: i64::from_be_bytes(tlv.data.try_into()?),
            })
        } else {
            Err(TCPLibError::Generic)
        }
    }
}

impl Answer {
    pub fn encode(self) -> Box<[u8]> {
        Tlv::encode(TlvType::Numi64, &self.num.to_be_bytes()).unwrap()
    }
}

impl From<i64> for Answer {
    fn from(num: i64) -> Self {
        Self { num }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Operation {
    Sum { a: u8, b: u8 },
    Sub { a: u8, b: u8 },
    Mul { a: u8, b: u8 },
    Div { a: u8, b: u8 },
    Rem { a: u8, b: u8 },
    Fact(u8),
}

impl Operation {
    pub fn reduce(self) -> i64 {
        match self {
            Operation::Sum { a, b } => (a as u16 + b as u16).into(),
            Operation::Sub { a, b } => (a as i16 - b as i16).into(),
            Operation::Mul { a, b } => (a as u16 * b as u16).into(),
            Operation::Div { a, b } => (a / b).into(),
            Operation::Rem { a, b } => (a % b).into(),
            Operation::Fact(0) => 1,
            Operation::Fact(a) => (1..=a as i64)
                .reduce(|acc, e| acc.saturating_mul(e))
                .unwrap(),
        }
    }
    pub fn encode(self) -> Box<[u8]> {
        match self {
            Operation::Sum { a, b } => Tlv::encode(TlvType::Sum, &[a, b]).unwrap(),
            Operation::Sub { a, b } => Tlv::encode(TlvType::Sub, &[a, b]).unwrap(),
            Operation::Mul { a, b } => Tlv::encode(TlvType::Mul, &[a, b]).unwrap(),
            Operation::Div { a, b } => Tlv::encode(TlvType::Div, &[a, b]).unwrap(),
            Operation::Rem { a, b } => Tlv::encode(TlvType::Rem, &[a, b]).unwrap(),
            Operation::Fact(a) => Tlv::encode(TlvType::Fact, &[a]).unwrap(),
        }
    }
}

impl<'a> TryFrom<Tlv<'a>> for Operation {
    type Error = TCPLibError;

    fn try_from(tlv: Tlv) -> Result<Self, Self::Error> {
        Ok(match tlv.tag {
            TlvType::Sum if tlv.length == 2 => Operation::Sum {
                a: tlv.data[0],
                b: tlv.data[1],
            },
            TlvType::Sub if tlv.length == 2 => Operation::Sub {
                a: tlv.data[0],
                b: tlv.data[1],
            },
            TlvType::Mul if tlv.length == 2 => Operation::Mul {
                a: tlv.data[0],
                b: tlv.data[1],
            },
            TlvType::Div if tlv.length == 2 && tlv.data[1] != 0 => Operation::Div {
                a: tlv.data[0],
                b: tlv.data[1],
            },
            TlvType::Rem if tlv.length == 2 && tlv.data[1] != 0 => Operation::Rem {
                a: tlv.data[0],
                b: tlv.data[1],
            },
            TlvType::Fact if tlv.length == 1 => Operation::Fact(tlv.data[0]),
            _ => return Err(TCPLibError::Generic),
        })
    }
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Sum { a, b } => write!(f, "{a}+{b}"),
            Operation::Sub { a, b } => write!(f, "{a}-{b}"),
            Operation::Mul { a, b } => write!(f, "{a}×{b}"),
            Operation::Div { a, b } => write!(f, "{a}÷{b}"),
            Operation::Rem { a, b } => write!(f, "{a}%{b}"),
            Operation::Fact(a) => write!(f, "{a}!"),
        }
    }
}

impl FromStr for Operation {
    type Err = TCPLibError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let regex = Regex::new(r"^\s*([0-9]+)\s*([+\-*×x/÷%!])\s*([0-9]+)?").unwrap();
        let elements: Box<_> = match regex.captures(s) {
            Some(captures) => captures.iter().skip(1).collect(),
            None => return Err(TCPLibError::Parse),
        };

        let (a, b) = match elements[..] {
            [Some(match_a), Some(_), Some(match_b)] => {
                (match_a.as_str().parse()?, match_b.as_str().parse()?)
            }
            [Some(match_a), Some(_), None] => (match_a.as_str().parse()?, 0u8),
            _ => {
                return Err(TCPLibError::Parse);
            }
        };

        let operation = match elements[1].map(|m| m.as_str()) {
            Some("+") if elements[2].is_some() => Operation::Sum { a, b },
            Some("-") if elements[2].is_some() => Operation::Sub { a, b },
            Some("*" | "×" | "x") if elements[2].is_some() => Operation::Mul { a, b },
            Some("/" | "÷") if elements[2].is_some() => Operation::Div { a, b },
            Some("%") if elements[2].is_some() => Operation::Rem { a, b },
            Some("!") if elements[2].is_none() => Operation::Fact(a),
            Some(op) => return Err(TCPLibError::UnsupportedOperation(op.to_string())),
            None => return Err(TCPLibError::Parse),
        };

        Ok(operation)
    }
}
