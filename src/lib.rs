use regex::Regex;
use std::{fmt::Display, str::FromStr};
use thiserror::Error;
use tlv::TlvType;

mod tlv;

pub use tlv::Tlv;
pub use tlv::TlvIterator;

#[derive(Clone, Error, Debug)]
pub enum TCPLibError {
    #[error("Something wrong")]
    Generic,
}

#[derive(Debug)]
pub struct Answer {
    pub num: i64,
}

impl<'a> TryFrom<Tlv<'a>> for Answer {
    type Error = anyhow::Error;

    fn try_from(tlv: Tlv) -> Result<Self, Self::Error> {
        if tlv.tag == TlvType::Numi64 && tlv.length == 8 {
            Ok(Answer {
                num: i64::from_be_bytes(tlv.data.try_into()?),
            })
        } else {
            Err(TCPLibError::Generic.into())
        }
    }
}

impl Answer {
    pub fn encode(self) -> Box<[u8]> {
        [TlvType::Numi64 as u8, 8]
            .iter()
            .chain(&self.num.to_be_bytes())
            .copied()
            .collect()
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
            Operation::Sum { a, b } => (a + b).into(),
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
            Operation::Sum { a, b } => [TlvType::Sum as u8, 2, a, b].iter().copied().collect(),
            Operation::Sub { a, b } => [TlvType::Sub as u8, 2, a, b].iter().copied().collect(),
            Operation::Mul { a, b } => [TlvType::Mul as u8, 2, a, b].iter().copied().collect(),
            Operation::Div { a, b } => [TlvType::Div as u8, 2, a, b].iter().copied().collect(),
            Operation::Rem { a, b } => [TlvType::Rem as u8, 2, a, b].iter().copied().collect(),
            Operation::Fact(a) => [TlvType::Fact as u8, 1, a].iter().copied().collect(),
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
            Operation::Div { a, b } => write!(f, "{a}/{b}"),
            Operation::Rem { a, b } => write!(f, "{a}%{b}"),
            Operation::Fact(a) => write!(f, "{a}!"),
        }
    }
}

impl FromStr for Operation {
    type Err = TCPLibError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let regex = Regex::new(r"^\s*([0-9]+)\s*([+\-*/%!])\s*([0-9]+)?").unwrap();
        let elements: Vec<_> = match regex.captures(s) {
            Some(captures) => captures.iter().skip(1).collect(),
            None => return Err(TCPLibError::Generic),
        };

        let (a, b) = match elements[..] {
            [Some(match_a), Some(_), Some(match_b)] => (
                match_a.as_str().parse().map_err(|_| TCPLibError::Generic)?,
                match_b.as_str().parse().map_err(|_| TCPLibError::Generic)?,
            ),
            [Some(match_a), Some(_), None] => (
                match_a.as_str().parse().map_err(|_| TCPLibError::Generic)?,
                0u8,
            ),
            _ => {
                return Err(TCPLibError::Generic);
            }
        };

        let operation = match elements[1].unwrap().as_str() {
            "+" if elements[2].is_some() => Operation::Sum { a, b },
            "-" if elements[2].is_some() => Operation::Sub { a, b },
            "*" if elements[2].is_some() => Operation::Mul { a, b },
            "/" if elements[2].is_some() => Operation::Div { a, b },
            "%" if elements[2].is_some() => Operation::Rem { a, b },
            "!" if elements[2].is_none() => Operation::Fact(a),
            _ => {
                return Err(TCPLibError::Generic);
            }
        };

        Ok(operation)
    }
}
