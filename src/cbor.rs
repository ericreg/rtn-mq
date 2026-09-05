//! Fixed, definite-length schemas. Callers must check canonical re-encoding before accepting input.
use crate::{Error, Result};
pub(crate) struct Writer(minicbor::Encoder<Vec<u8>>);
impl Writer {
    pub fn new() -> Self {
        Self(minicbor::Encoder::new(Vec::new()))
    }
    pub fn array(&mut self, len: usize) {
        self.0.array(len as u64).unwrap();
    }
    pub fn u(&mut self, n: u64) {
        self.0.u64(n).unwrap();
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.0.bytes(b).unwrap();
    }
    pub fn text(&mut self, s: &str) {
        self.0.str(s).unwrap();
    }
    pub fn empty_map(&mut self) {
        self.0.map(0).unwrap();
    }
    pub fn finish(self) -> Vec<u8> {
        self.0.into_writer()
    }
}
pub(crate) struct Reader<'a>(minicbor::Decoder<'a>);
impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self(minicbor::Decoder::new(b))
    }
    pub fn array(&mut self, len: usize) -> Result<()> {
        if self.0.array()? != Some(len as u64) {
            return Err(Error::Protocol("array length"));
        }
        Ok(())
    }
    pub fn list(&mut self, max: usize) -> Result<usize> {
        let n = self.0.array()?.ok_or(Error::Protocol("indefinite array"))?;
        if n > max as u64 {
            return Err(Error::Protocol("collection limit"));
        }
        Ok(n as usize)
    }
    pub fn u(&mut self) -> Result<u64> {
        Ok(self.0.u64()?)
    }
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let b = self.0.bytes()?;
        if b.len() > max {
            return Err(Error::MessageTooLarge);
        }
        Ok(b)
    }
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| Error::Protocol("byte string length"))
    }
    pub fn text(&mut self, max: usize) -> Result<&'a str> {
        let s = self.0.str()?;
        if s.len() > max {
            return Err(Error::MessageTooLarge);
        }
        Ok(s)
    }
    pub fn empty_map(&mut self) -> Result<()> {
        if self.0.map()? != Some(0) {
            return Err(Error::Protocol("unprotected headers"));
        }
        Ok(())
    }
    pub fn end(self) -> Result<()> {
        if self.0.position() != self.0.input().len() {
            return Err(Error::Protocol("trailing bytes"));
        }
        Ok(())
    }
}
pub(crate) fn canonical(input: &[u8], encoded: &[u8]) -> Result<()> {
    if input != encoded {
        return Err(Error::Protocol("noncanonical CBOR"));
    }
    Ok(())
}
