pub struct Reader<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> From<&'a [u8]> for Reader<'a> {
    fn from(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Reader<'a> {
    pub fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }

    pub fn get_u8(&mut self) -> u8 {
        let ret = self.buf[self.pos];
        self.pos += 1;
        ret
    }

    pub fn get_u16(&mut self) -> u16 {
        let ret = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        ret
    }

    pub fn read(&mut self, len: usize) -> &'a [u8] {
        let start = self.pos;
        self.pos += len;
        &self.buf[start..self.pos]
    }

    pub fn read8(&mut self) -> &'a [u8] {
        let start = self.pos;
        let len = self.buf[self.pos] as usize;
        self.pos += 1 + len;
        &self.buf[start..self.pos]
    }

    pub fn read16(&mut self) -> &'a [u8] {
        let start = self.pos;
        let len = u16::from_be_bytes([self.buf[start], self.buf[start + 1]]) as usize;
        self.pos += 2 + len;
        &self.buf[start..self.pos]
    }

    pub fn read16_at(&mut self, offset: usize) -> &'a [u8] {
        let start = self.pos;
        let length = u16::from_be_bytes([self.buf[start + offset], self.buf[start + offset + 1]]) as usize;
        self.pos += offset + 2 + length;
        &self.buf[start..self.pos]
    }

    pub fn read24(&mut self) -> &'a [u8] {
        let start = self.pos;
        let len = u32::from_be_bytes([0, self.buf[start], self.buf[start + 1], self.buf[start + 2]])
            as usize;
        self.pos += 3 + len;
        &self.buf[start..self.pos]
    }
}
