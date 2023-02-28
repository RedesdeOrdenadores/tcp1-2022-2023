use thiserror::Error;

#[derive(Clone, Error, Debug)]
pub enum TlvError {
    #[error("Unknown tag")]
    TagUnknown(u8),
    #[error("Wrong format for tag")]
    WrongFormat,
    #[error("Too much data to be encoded")]
    ExcessiveLength(usize),
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

#[derive(Debug)]
pub struct Tlv<'a> {
    pub tag: TlvType,
    pub length: u8,
    pub data: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn encode(tag: TlvType, data: &[u8]) -> Result<Box<[u8]>, TlvError> {
        if let Ok(length) = u8::try_from(data.len()) {
            let mut res = vec![tag as u8, length];
            res.extend(data);

            Ok(res.into_boxed_slice())
        } else {
            Err(TlvError::ExcessiveLength(data.len()))
        }
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
