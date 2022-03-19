use exe::*;
use compression::prelude::*;

pub struct OxideData {
    pub size: u64,
    pub data: Vec<u8>,
}
impl OxideData {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let buffer = Buffer::new(data);

        let size = match buffer.get_ref::<u64>(Offset(0)) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if (*size as usize) < (data.len()-8) {
            return Err(Error::BufferTooSmall);
        }

        Ok(Self {
            size: *size,
            data: buffer.read(Offset(8), *size as usize).unwrap().iter().cloned().collect(),
        })
    }

    pub fn pack(data: &[u8]) -> Self {
        let compressed = data.into_iter()
            .cloned()
            .encode(&mut BZip2Encoder::new(9), Action::Finish)
            .collect::<Result<Vec<u8>, _>>()
            .unwrap();

        Self {
            size: compressed.len() as u64,
            data: compressed,
        }
    }

    pub fn unpack(&self) -> Vec<u8> {
        self.data.as_slice()
            .into_iter()
            .cloned()
            .decode(&mut BZip2Decoder::new())
            .collect::<Result<Vec<u8>, _>>()
            .unwrap()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec = vec![0u8; self.data.len()+std::mem::size_of::<u64>()];
        let mut buffer = Buffer::new_mut(vec.as_mut_slice());

        buffer.write_ref(Offset(0), &(self.data.len() as u64)).unwrap();
        buffer.write(Offset(8), self.data.as_slice()).unwrap();

        buffer.as_slice().iter().cloned().collect()
    }
}
