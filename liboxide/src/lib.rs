use compression::prelude::*;

use pkbuffer::Error as PKError;
use pkbuffer::*;

#[derive(Debug)]
pub enum Error {
    CompressionError(CompressionError),
    BZip2Error(BZip2Error),
    PKError(PKError),
    DataIsTruncated(usize,usize),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CompressionError(ref e) => write!(f, "compression error: {}", e.to_string()),
            Error::BZip2Error(ref e) => write!(f, "bzip2 error: {}", e.to_string()),
            Error::PKError(ref e) => write!(f, "pkbuffer error: {}", e.to_string()),
            Error::DataIsTruncated(expected,got) => write!(f, "data is truncated: expected length {}, got {}", expected, got),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::CompressionError(ref e) => Some(e),
            Error::BZip2Error(ref e) => Some(e),
            Error::PKError(ref e) => Some(e),
            _ => None,
        }
    }
}
impl From<CompressionError> for Error {
    fn from(err: CompressionError) -> Self {
        Self::CompressionError(err)
    }
}
impl From<BZip2Error> for Error {
    fn from(err: BZip2Error) -> Self {
        Self::BZip2Error(err)
    }
}
impl From<PKError> for Error {
    fn from(err: PKError) -> Self {
        Self::PKError(err)
    }
}

pub struct OxideData {
    pub size: u64,
    pub data: Vec<u8>,
}
impl OxideData {
    pub fn parse<B: AsRef<[u8]>>(data: B) -> Result<Self, Error> {
        let buf = data.as_ref();
        let buffer = VecBuffer::from_data(buf);

        let size = buffer.get_ref::<u64>(0)?;

        if (*size as usize) > (buf.len()-8) {
            return Err(Error::DataIsTruncated(buf.len()-8, *size as usize));
        }

        let read_data = match buffer.read(8, *size as usize) {
            Ok(d) => d.to_vec(),
            Err(e) => return Err(From::from(e)),
        };

        Ok(Self {
            size: *size,
            data: read_data,
        })
    }

    pub fn pack<B: AsRef<[u8]>>(data: B) -> Result<Self, Error> {
        let buf = data.as_ref();
        let compressed = buf.iter()
            .cloned()
            .encode(&mut BZip2Encoder::new(9), Action::Finish)
            .collect::<Result<Vec<u8>, CompressionError>>()?;

        Ok(Self {
            size: compressed.len() as u64,
            data: compressed,
        })
    }

    pub fn unpack(&self) -> Result<Vec<u8>, Error> {
        let result = self.data.iter()
            .cloned()
            .decode(&mut BZip2Decoder::new())
            .collect::<Result<Vec<u8>, BZip2Error>>()?;
        Ok(result)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buffer = VecBuffer::new();

        buffer.append_ref(&(self.data.len() as u64))?;
        buffer.append(&self.data);

        Ok(buffer.to_vec())
    }
}
