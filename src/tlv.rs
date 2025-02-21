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

use std::num::TryFromIntError;

use thiserror::Error;

#[derive(Clone, Error, Debug)]
pub enum TlvError {
    #[error("Unknown tag")]
    TagUnknown(u8),
    #[error("Wrong format for tag")]
    WrongFormat,
    #[error("Too much data to be encoded")]
    ExcessiveLength(#[from] TryFromIntError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum TlvType {
    Sum = 1,
    Sub = 2,
    Mul = 3,
    Div = 4,
    Rem = 5,
    Fact = 6,
    Numi64 = 16,
}

impl TryFrom<u8> for TlvType {
    type Error = TlvError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == TlvType::Sum as u8 => Ok(TlvType::Sum),
            x if x == TlvType::Sub as u8 => Ok(TlvType::Sub),
            x if x == TlvType::Mul as u8 => Ok(TlvType::Mul),
            x if x == TlvType::Div as u8 => Ok(TlvType::Div),
            x if x == TlvType::Rem as u8 => Ok(TlvType::Rem),
            x if x == TlvType::Fact as u8 => Ok(TlvType::Fact),
            x if x == TlvType::Numi64 as u8 => Ok(TlvType::Numi64),
            x => Err(TlvError::TagUnknown(x)),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Tlv<'a> {
    pub tag: TlvType,
    pub length: u8,
    pub data: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn new(tag: TlvType, data: &'a [u8]) -> Result<Self, TlvError> {
        Ok(Self {
            tag,
            length: data.len().try_into()?,
            data,
        })
    }

    pub fn encode(self) -> Box<[u8]> {
        [self.tag as u8, self.length]
            .iter()
            .chain(self.data)
            .copied()
            .collect()
    }
}

impl<'a> TryFrom<&'a [u8]> for Tlv<'a> {
    type Error = TlvError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        match bytes.len() {
            2.. if bytes.len() >= (bytes[1] + 2).into() => Ok(Tlv {
                tag: bytes[0].try_into()?,
                length: bytes[1],
                data: &bytes[2..(2 + bytes[1]).into()],
            }),
            _ => Err(TlvError::WrongFormat),
        }
    }
}

pub struct TlvIterator<'a> {
    buf: &'a [u8],
    index: usize,
}

impl<'a> TlvIterator<'a> {
    pub fn process(buf: &'a [u8]) -> Self {
        Self { buf, index: 0 }
    }
}

impl<'a> Iterator for TlvIterator<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match Tlv::try_from(&self.buf[self.index..]) {
            Ok(tlv) => {
                self.index += 2 + tlv.length as usize;
                Some(tlv)
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Tlv, TlvIterator};

    #[test]
    fn parse_tlv_err_long() {
        let tlv: Result<Tlv, _> = (&[16u8, 9, 0, 0, 0, 0, 0, 0, 0, 1][..]).try_into();
        assert!(tlv.is_err());
    }

    #[test]
    fn parse_tlv_err_type() {
        let tlv: Result<Tlv, _> = (&[20u8, 8, 0, 0, 0, 0, 0, 0, 0, 1][..]).try_into();
        assert!(tlv.is_err());
    }

    #[test]
    fn parse_tlv_iter() {
        let mut iterator = TlvIterator::process(&[
            1u8, 2, 0, 0, 1u8, 4, 0, 0, 0, 0, 1u8, 1, 1, 1u8, 0, 1u8, 1, 2,
        ]);

        assert_eq!(
            iterator.next(),
            Some(Tlv {
                tag: 1u8.try_into().unwrap(),
                length: 2,
                data: &[0, 0]
            })
        );
        assert_eq!(
            iterator.next(),
            Some(Tlv {
                tag: 1u8.try_into().unwrap(),
                length: 4,
                data: &[0, 0, 0, 0]
            })
        );
        assert_eq!(
            iterator.next(),
            Some(Tlv {
                tag: 1u8.try_into().unwrap(),
                length: 1,
                data: &[1]
            })
        );
        assert_eq!(
            iterator.next(),
            Some(Tlv {
                tag: 1u8.try_into().unwrap(),
                length: 0,
                data: &[]
            })
        );
        assert_eq!(
            iterator.next(),
            Some(Tlv {
                tag: 1u8.try_into().unwrap(),
                length: 1,
                data: &[2]
            })
        );
        assert_eq!(iterator.next(), None);
    }
}
