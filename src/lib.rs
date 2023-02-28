use operation::OperationError;
use std::array::TryFromSliceError;
use std::num::{ParseIntError, TryFromIntError};
use std::u8;

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
