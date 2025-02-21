// SPDX-License-Identifier: GPL-3.0-or-later
/*
 *
 * Copyright (c) 2023 Universidade de Vigo
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

use operation::OperationError;
use std::array::TryFromSliceError;
use std::num::{ParseIntError, TryFromIntError};

use thiserror::Error;
use tlv::TlvType;

mod operation;
mod tlv;

pub use operation::Operation;
pub use tlv::Tlv;
pub use tlv::TlvIterator;

#[derive(Clone, Error, Debug)]
pub enum TCPLibError {
    #[error("Operation error")]
    OperationError(#[from] OperationError),
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

#[derive(Debug, PartialEq)]
pub struct Answer(pub i64);

impl TryFrom<Tlv<'_>> for Answer {
    type Error = TCPLibError;

    fn try_from(tlv: Tlv) -> Result<Self, Self::Error> {
        if tlv.tag == TlvType::Numi64 && tlv.length == 8 {
            Ok(Answer(i64::from_be_bytes(tlv.data.try_into()?)))
        } else {
            Err(TCPLibError::Generic)
        }
    }
}

impl Answer {
    pub fn encode(self) -> Box<[u8]> {
        Tlv::new(TlvType::Numi64, &self.0.to_be_bytes())
            .unwrap()
            .encode()
    }
}

impl From<i64> for Answer {
    fn from(num: i64) -> Self {
        Self(num)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Answer, Tlv};

    #[test]
    fn parse_answer_1() {
        let tlv: Result<Tlv, _> = (&[16u8, 8, 0, 0, 0, 0, 0, 0, 0, 1][..]).try_into();
        assert!(tlv.is_ok());
        let answer: Result<Answer, _> = tlv.unwrap().try_into();
        assert!(answer.is_ok());
        assert_eq!(answer.unwrap(), 1.into());
    }

    #[test]
    fn parse_answer_minus1() {
        let tlv: Result<Tlv, _> =
            (&[16u8, 8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..]).try_into();
        assert!(tlv.is_ok());
        let answer: Result<Answer, _> = tlv.unwrap().try_into();
        assert!(answer.is_ok());
        assert_eq!(answer.unwrap(), (-1).into());
    }

    #[test]
    fn parse_answer_err_short() {
        let tlv: Result<Tlv, _> = (&[16u8, 7, 0, 0, 0, 0, 0, 0, 0, 1][..]).try_into();
        assert!(tlv.is_ok());
        let answer: Result<Answer, _> = tlv.unwrap().try_into();
        assert!(answer.is_err());
    }

    #[test]
    fn encode_answer() {
        assert_eq!(Answer(1).encode()[..], [16u8, 8, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            Answer(-1).encode()[..],
            [16u8, 8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }
}
