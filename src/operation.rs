// SPDX-License-Identifier: GPL-3.0-or-later
/*
 *
 * Copyright (c) 2023–2025 Universidade de Vigo
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Miguel Rodríguez Pérez <miguel@det.uvigo.gal>
 *
 */

use std::{
    array::TryFromSliceError,
    fmt::Display,
    num::{NonZeroI8, ParseIntError, TryFromIntError},
    str::FromStr,
};

use regex::Regex;
use thiserror::Error;

use crate::{Tlv, tlv::TlvType};

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

#[derive(Clone, Debug, PartialEq)]
pub struct BinomialOperationData<T1, T2>(T1, T2);

#[derive(Clone, Debug, PartialEq)]
pub struct MonomialOperationData<T1>(T1);

impl<T1, T2> BinomialOperationData<T1, T2>
where
    T1: Into<i8>,
    T2: Into<i8>,
{
    pub fn encode(self) -> [u8; 2] {
        [self.0.into() as u8, self.1.into() as u8]
    }
}

impl<T1> MonomialOperationData<T1>
where
    T1: Into<i8>,
{
    pub fn encode(self) -> [u8; 1] {
        self.0.into().to_be_bytes()
    }
}

impl From<[u8; 2]> for BinomialOperationData<i8, i8> {
    fn from(value: [u8; 2]) -> Self {
        (i8::from_be_bytes([value[0]]), i8::from_be_bytes([value[1]])).into()
    }
}

impl TryFrom<[u8; 2]> for BinomialOperationData<i8, NonZeroI8> {
    type Error = OperationError;

    fn try_from(value: [u8; 2]) -> Result<Self, Self::Error> {
        Ok((
            i8::from_be_bytes([value[0]]),
            i8::from_be_bytes([value[1]]).try_into()?,
        )
            .into())
    }
}

impl From<[u8; 1]> for MonomialOperationData<i8> {
    fn from(value: [u8; 1]) -> Self {
        Self(i8::from_be_bytes(value))
    }
}

impl<T2> From<(i8, T2)> for BinomialOperationData<i8, T2>
where
    T2: Into<i8>,
{
    fn from((a, b): (i8, T2)) -> Self {
        Self(a, b)
    }
}

impl From<i8> for MonomialOperationData<i8> {
    fn from(a: i8) -> Self {
        Self(a)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Operation {
    Sum(BinomialOperationData<i8, i8>),
    Sub(BinomialOperationData<i8, i8>),
    Mul(BinomialOperationData<i8, i8>),
    Div(BinomialOperationData<i8, NonZeroI8>),
    Rem(BinomialOperationData<i8, NonZeroI8>),
    Fact(MonomialOperationData<i8>),
}

impl Operation {
    pub fn reduce(&self) -> Result<i64, OperationError> {
        Ok(match *self {
            Operation::Sum(BinomialOperationData(a, b)) => (a as i16 + b as i16).into(),
            Operation::Sub(BinomialOperationData(a, b)) => (a as i16 - b as i16).into(),
            Operation::Mul(BinomialOperationData(a, b)) => (a as i16 * b as i16).into(),
            Operation::Div(BinomialOperationData(a, b)) => (a / b.get()).into(),
            Operation::Rem(BinomialOperationData(a, b)) => (a % b.get()).into(),
            Operation::Fact(MonomialOperationData(0)) => 1,
            Operation::Fact(MonomialOperationData(a)) if a > 0 => (1..=a as i64)
                .reduce(|acc, e| acc.saturating_mul(e))
                .unwrap(),
            _ => return Err(OperationError::WrongDomain),
        })
    }
    pub fn encode(self) -> Box<[u8]> {
        match self {
            Operation::Sum(data) => Tlv::new(TlvType::Sum, &data.encode()).unwrap().encode(),
            Operation::Sub(data) => Tlv::new(TlvType::Sub, &data.encode()).unwrap().encode(),
            Operation::Mul(data) => Tlv::new(TlvType::Mul, &data.encode()).unwrap().encode(),
            Operation::Div(data) => Tlv::new(TlvType::Div, &data.encode()).unwrap().encode(),
            Operation::Rem(data) => Tlv::new(TlvType::Rem, &data.encode()).unwrap().encode(),
            Operation::Fact(data) => Tlv::new(TlvType::Fact, &data.encode()).unwrap().encode(),
        }
    }
}

impl TryFrom<Tlv<'_>> for Operation {
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
            Operation::Sum(BinomialOperationData(a, b)) => write!(f, "{}+{}", a, b),
            Operation::Sub(BinomialOperationData(a, b)) => write!(f, "{}-{}", a, b),
            Operation::Mul(BinomialOperationData(a, b)) => write!(f, "{}×{}", a, b),
            Operation::Div(BinomialOperationData(a, b)) => write!(f, "{}÷{}", a, b),
            Operation::Rem(BinomialOperationData(a, b)) => write!(f, "{}%{}", a, b),
            Operation::Fact(MonomialOperationData(a)) => write!(f, "{}!", a),
        }
    }
}

impl FromStr for Operation {
    type Err = OperationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let regex = Regex::new(r"^\s*(\-?\d+)\s*([+\-*×x/÷%!])\s*(\-?\d+)?\s*$").unwrap();
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

#[cfg(test)]
mod tests {
    use crate::{Operation, Tlv};

    #[test]
    fn parse_operation_sum() {
        let tlv: Result<Tlv, _> = (&[1u8, 2, 127, 255][..]).try_into();
        assert!(tlv.is_ok());
        let operation: Result<Operation, _> = tlv.unwrap().try_into();
        assert!(operation.is_ok());
        assert_eq!(operation.unwrap(), Operation::Sum((127, -1).into()));
    }

    #[test]
    fn parse_operation_div_zero() {
        let tlv: Result<Tlv, _> = (&[4u8, 2, 100, 0][..]).try_into();
        assert!(tlv.is_ok());
        let operation: Result<Operation, _> = tlv.unwrap().try_into();
        assert!(operation.is_err());
    }

    #[test]
    fn parse_operation_rem_zero() {
        let tlv: Result<Tlv, _> = (&[5u8, 2, 100, 0][..]).try_into();
        assert!(tlv.is_ok());
        let operation: Result<Operation, _> = tlv.unwrap().try_into();
        assert!(operation.is_err());
    }

    #[test]
    fn operation_fact_negative() {
        assert!(Operation::Fact((-1).into()).reduce().is_err());
    }

    #[test]
    fn operation_fact_zero() {
        let res = Operation::Fact((0).into()).reduce();
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 1);
    }

    #[test]
    fn encode_sub() {
        assert_eq!(
            Operation::Sub((10, -10).into()).encode()[..],
            [2u8, 2, 10, 246]
        );
    }

    #[test]
    fn encode_fact() {
        assert_eq!(Operation::Fact((100).into()).encode()[..], [6u8, 1, 100]);
    }
}
