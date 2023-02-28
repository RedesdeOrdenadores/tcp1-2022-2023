use std::{
    array::TryFromSliceError,
    fmt::Display,
    marker::PhantomData,
    num::{NonZeroI8, ParseIntError, TryFromIntError},
    str::FromStr,
};

use regex::Regex;
use thiserror::Error;

use crate::{tlv::TlvType, Tlv};

use self::detail::OperationData;

#[derive(Clone, Error, Debug)]
pub enum OperationError {
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
    #[error("Wrong domain")]
    WrongDomain,
    #[error("Something wrong")]
    Generic,
}

mod detail {
    use std::marker::PhantomData;

    #[derive(Debug, Clone, Copy)]
    pub struct OperationData<T1, T2 = PhantomData<T1>, const N: usize = 1> {
        pub a: T1,
        pub b: T2,
    }
}

pub type BinomialOperationData<T1, T2> = OperationData<T1, T2, 2>;
pub type MonomialOperationData<T1> = OperationData<T1, PhantomData<T1>, 1>;

impl<T1, T2> BinomialOperationData<T1, T2>
where
    T1: Into<i8>,
    T2: Into<i8>,
{
    pub fn encode(self) -> [u8; 2] {
        [self.a.into() as u8, self.b.into() as u8]
    }
}

impl<T1> MonomialOperationData<T1>
where
    T1: Into<i8>,
{
    pub fn encode(self) -> [u8; 1] {
        [self.a.into() as u8]
    }
}

impl From<[u8; 2]> for BinomialOperationData<i8, i8> {
    fn from(value: [u8; 2]) -> Self {
        (value[0] as i8, value[1] as i8).into()
    }
}

impl TryFrom<[u8; 2]> for BinomialOperationData<i8, NonZeroI8> {
    type Error = OperationError;

    fn try_from(value: [u8; 2]) -> Result<Self, Self::Error> {
        Ok((value[0] as i8, (value[1] as i8).try_into()?).into())
    }
}

impl From<[u8; 1]> for MonomialOperationData<i8> {
    fn from(value: [u8; 1]) -> Self {
        (value[0] as i8).into()
    }
}

impl From<(i8, i8)> for BinomialOperationData<i8, i8> {
    fn from((a, b): (i8, i8)) -> Self {
        Self { a, b }
    }
}

impl From<(i8, NonZeroI8)> for BinomialOperationData<i8, NonZeroI8> {
    fn from((a, b): (i8, NonZeroI8)) -> Self {
        Self { a, b }
    }
}

impl From<i8> for MonomialOperationData<i8> {
    fn from(a: i8) -> Self {
        Self { a, b: PhantomData }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Operation {
    Sum(BinomialOperationData<i8, i8>),
    Sub(BinomialOperationData<i8, i8>),
    Mul(BinomialOperationData<i8, i8>),
    Div(BinomialOperationData<i8, NonZeroI8>),
    Rem(BinomialOperationData<i8, NonZeroI8>),
    Fact(MonomialOperationData<i8>),
}

impl Operation {
    pub fn reduce(self) -> Result<i64, OperationError> {
        Ok(match self {
            Operation::Sum(data) => (data.a as i16 + data.b as i16).into(),
            Operation::Sub(data) => (data.a as i16 - data.b as i16).into(),
            Operation::Mul(data) => (data.a as i16 * data.b as i16).into(),
            Operation::Div(data) => (data.a / data.b.get()).into(),
            Operation::Rem(data) => (data.a % data.b.get()).into(),
            Operation::Fact(data) if data.a == 0 => 1,
            Operation::Fact(data) if data.a > 0 => (1..=data.a as i64)
                .reduce(|acc, e| acc.saturating_mul(e))
                .unwrap(),
            _ => return Err(OperationError::WrongDomain),
        })
    }
    pub fn encode(self) -> Box<[u8]> {
        match self {
            Operation::Sum(data) => Tlv::encode(TlvType::Sum, &data.encode()).unwrap(),
            Operation::Sub(data) => Tlv::encode(TlvType::Sub, &data.encode()).unwrap(),
            Operation::Mul(data) => Tlv::encode(TlvType::Mul, &data.encode()).unwrap(),
            Operation::Div(data) => Tlv::encode(TlvType::Div, &data.encode()).unwrap(),
            Operation::Rem(data) => Tlv::encode(TlvType::Rem, &data.encode()).unwrap(),
            Operation::Fact(data) => Tlv::encode(TlvType::Fact, &data.encode()).unwrap(),
        }
    }
}

impl<'a> TryFrom<Tlv<'a>> for Operation {
    type Error = OperationError;

    fn try_from(tlv: Tlv) -> Result<Self, Self::Error> {
        Ok(match tlv.tag {
            TlvType::Sum if tlv.length == 2 => {
                Operation::Sum(<[u8; 2]>::try_from(tlv.data)?.into())
            }
            TlvType::Sub if tlv.length == 2 => {
                Operation::Sub(<[u8; 2]>::try_from(tlv.data)?.into())
            }
            TlvType::Mul if tlv.length == 2 => {
                Operation::Mul(<[u8; 2]>::try_from(tlv.data)?.into())
            }
            TlvType::Div if tlv.length == 2 => {
                Operation::Div(<[u8; 2]>::try_from(tlv.data)?.try_into()?)
            }
            TlvType::Rem if tlv.length == 2 => {
                Operation::Rem(<[u8; 2]>::try_from(tlv.data)?.try_into()?)
            }
            TlvType::Fact if tlv.length == 1 => {
                Operation::Fact(<[u8; 1]>::try_from(tlv.data)?.into())
            }
            _ => return Err(OperationError::Generic),
        })
    }
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Sum(data) => write!(f, "{}+{}", data.a, data.b),
            Operation::Sub(data) => write!(f, "{}-{}", data.a, data.b),
            Operation::Mul(data) => write!(f, "{}×{}", data.a, data.b),
            Operation::Div(data) => write!(f, "{}÷{}", data.a, data.b),
            Operation::Rem(data) => write!(f, "{}%{}", data.a, data.b),
            Operation::Fact(data) => write!(f, "{}!", data.a),
        }
    }
}

impl FromStr for Operation {
    type Err = OperationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let regex = Regex::new(r"^\s*(\-?[0-9]+)\s*([+\-*×x/÷%!])\s*(\-?[0-9]+)?\s*$").unwrap();
        let elements: Box<_> = match regex.captures(s) {
            Some(captures) => captures.iter().skip(1).collect(),
            None => return Err(OperationError::Parse),
        };

        let (a, b) = match elements[..] {
            [Some(match_a), Some(_), Some(match_b)] => {
                (match_a.as_str().parse()?, match_b.as_str().parse()?)
            }
            [Some(match_a), Some(_), None] => (match_a.as_str().parse()?, 0i8),
            _ => {
                return Err(OperationError::Parse);
            }
        };

        let operation = match elements[1].map(|m| m.as_str()) {
            Some("+") if elements[2].is_some() => Operation::Sum((a, b).into()),
            Some("-") if elements[2].is_some() => Operation::Sub((a, b).into()),
            Some("*" | "×" | "x") if elements[2].is_some() => Operation::Mul((a, b).into()),
            Some("/" | "÷") if elements[2].is_some() => Operation::Div((a, b.try_into()?).into()),
            Some("%") if elements[2].is_some() => Operation::Rem((a, b.try_into()?).into()),
            Some("!") if elements[2].is_none() && a >= 0 => Operation::Fact(a.into()),
            Some(op) => return Err(OperationError::UnsupportedOperation(op.to_string())),
            None => return Err(OperationError::Parse),
        };

        Ok(operation)
    }
}
