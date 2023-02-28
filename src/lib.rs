use regex::Regex;
use std::array::TryFromSliceError;
use std::num::{NonZeroI8, ParseIntError, TryFromIntError};
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
    #[error("Invalid parameter")]
    InvalidParameter(#[from] TryFromIntError),
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
    Sum { a: i8, b: i8 },
    Sub { a: i8, b: i8 },
    Mul { a: i8, b: i8 },
    Div { a: i8, b: NonZeroI8 },
    Rem { a: i8, b: NonZeroI8 },
    Fact(u8),
}

impl Operation {
    pub fn reduce(self) -> i64 {
        match self {
            Operation::Sum { a, b } => (a as i16 + b as i16).into(),
            Operation::Sub { a, b } => (a as i16 - b as i16).into(),
            Operation::Mul { a, b } => (a as i16 * b as i16).into(),
            Operation::Div { a, b } => (a / b.get()).into(),
            Operation::Rem { a, b } => (a % b.get()).into(),
            Operation::Fact(0) => 1,
            Operation::Fact(a) => (1..=a as i64)
                .reduce(|acc, e| acc.saturating_mul(e))
                .unwrap(),
        }
    }
    pub fn encode(self) -> Box<[u8]> {
        match self {
            Operation::Sum { a, b } => Tlv::encode(TlvType::Sum, &[a as u8, b as u8]).unwrap(),
            Operation::Sub { a, b } => Tlv::encode(TlvType::Sub, &[a as u8, b as u8]).unwrap(),
            Operation::Mul { a, b } => Tlv::encode(TlvType::Mul, &[a as u8, b as u8]).unwrap(),
            Operation::Div { a, b } => {
                Tlv::encode(TlvType::Div, &[a as u8, b.get() as u8]).unwrap()
            }
            Operation::Rem { a, b } => {
                Tlv::encode(TlvType::Rem, &[a as u8, b.get() as u8]).unwrap()
            }
            Operation::Fact(a) => Tlv::encode(TlvType::Fact, &[a]).unwrap(),
        }
    }
}

impl<'a> TryFrom<Tlv<'a>> for Operation {
    type Error = TCPLibError;

    fn try_from(tlv: Tlv) -> Result<Self, Self::Error> {
        let data: Box<[_]> = tlv.data.iter().map(|&u| u as i8).collect();
        Ok(match tlv.tag {
            TlvType::Sum if tlv.length == 2 => Operation::Sum {
                a: data[0],
                b: data[1],
            },
            TlvType::Sub if tlv.length == 2 => Operation::Sub {
                a: data[0],
                b: data[1],
            },
            TlvType::Mul if tlv.length == 2 => Operation::Mul {
                a: data[0],
                b: data[1],
            },
            TlvType::Div if tlv.length == 2 => Operation::Div {
                a: data[0],
                b: data[1].try_into()?,
            },
            TlvType::Rem if tlv.length == 2 => Operation::Rem {
                a: data[0],
                b: data[1].try_into()?,
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
        let regex = Regex::new(r"^\s*(\-?[0-9]+)\s*([+\-*×x/÷%!])\s*(\-?[0-9]+)?\s*$").unwrap();
        let elements: Box<_> = match regex.captures(s) {
            Some(captures) => captures.iter().skip(1).collect(),
            None => return Err(TCPLibError::Parse),
        };

        let (a, b) = match elements[..] {
            [Some(match_a), Some(_), Some(match_b)] => {
                (match_a.as_str().parse()?, match_b.as_str().parse()?)
            }
            [Some(match_a), Some(_), None] => (match_a.as_str().parse()?, 0i8),
            _ => {
                return Err(TCPLibError::Parse);
            }
        };

        let operation = match elements[1].map(|m| m.as_str()) {
            Some("+") if elements[2].is_some() => Operation::Sum { a, b },
            Some("-") if elements[2].is_some() => Operation::Sub { a, b },
            Some("*" | "×" | "x") if elements[2].is_some() => Operation::Mul { a, b },
            Some("/" | "÷") if elements[2].is_some() => Operation::Div {
                a,
                b: b.try_into()?,
            },
            Some("%") if elements[2].is_some() => Operation::Rem {
                a,
                b: b.try_into()?,
            },
            Some("!") if elements[2].is_none() => Operation::Fact(a.try_into()?),
            Some(op) => return Err(TCPLibError::UnsupportedOperation(op.to_string())),
            None => return Err(TCPLibError::Parse),
        };

        Ok(operation)
    }
}
