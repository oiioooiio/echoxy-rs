use num_enum::{FromPrimitive, IntoPrimitive};

use super::common::Reader;

/// TLSError
#[derive(Debug)]
pub enum TLSError {
    TLSPlaintextTooShort,
    InvalidContentType(u8),
    InvalidHandshakeType(u8),
    HandshakeTooShort,
    InvalidECHClientHelloType(u8),
}

type ProtocolVersion = u16;

#[derive(Debug, PartialEq, FromPrimitive)]
#[repr(u8)]
pub enum ContentType {
    Handshake = 22,
    #[num_enum(catch_all)]
    Unknown(u8),
}

#[derive(Debug)]
pub struct TLSPlaintext<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for TLSPlaintext<'a> {
    type Error = TLSError;
    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        if data.len() < 5 {
            return Err(TLSError::TLSPlaintextTooShort);
        }

        let typ = data[0].into();
        let version = u16::from_be_bytes([data[1], data[2]]);
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;

        if data.len() < length + 5 {
            return Err(TLSError::TLSPlaintextTooShort);
        }

        Ok(TLSPlaintext {
            typ,
            version,
            payload: &data[5..length + 5],
        })
    }
}

#[derive(Debug, PartialEq, FromPrimitive)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello = 1,
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// Handshake
#[derive(Debug)]
pub struct Handshake<'a> {
    pub typ: HandshakeType,
    pub payload: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for Handshake<'a> {
    type Error = TLSError;
    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        if data.len() < 4 {
            return Err(TLSError::HandshakeTooShort);
        }

        let typ = data[0].into();
        let length = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;

        if data.len() < length + 4 {
            return Err(TLSError::HandshakeTooShort);
        }

        Ok(Handshake {
            typ,
            payload: &data[4..length + 4],
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, FromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum ExtensionType {
    ServerName = 0,
    OuterExtensions = 0xfd00,
    EncryptedClientHello = 0xfe0d,
    #[num_enum(catch_all)]
    Unknown(u16),
}

impl From<[u8; 2]> for ExtensionType {
    fn from(data: [u8; 2]) -> Self {
        u16::from_be_bytes(data).into()
    }
}

/// Extension
pub struct Extension<'a> {
    raw: &'a [u8],
}

impl<'a> Extension<'a> {
    pub fn typ(&self) -> ExtensionType {
        [self.raw[0], self.raw[1]].into()
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.raw[4..]
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
}

impl<'a> From<&'a [u8]> for Extension<'a> {
    fn from(data: &'a [u8]) -> Self {
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        Self {
            raw: &data[..length + 4],
        }
    }
}

impl std::fmt::Debug for Extension<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.typ())
    }
}

/// ClientHello
pub struct ClientHello<'a> {
    pub version: ProtocolVersion,
    pub random: &'a [u8],
    pub session: &'a [u8],
    pub cipher_suites: &'a [u8],
    pub compressions: &'a [u8],
    pub extensions: Vec<Extension<'a>>,
    pub raw: &'a [u8],
}

impl ClientHello<'_> {
    pub fn get_extension(&self, typ: ExtensionType) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.typ() == typ)
    }

    pub fn ech_extension(&self) -> Option<&Extension> {
        self.get_extension(ExtensionType::EncryptedClientHello)
    }

    pub fn outer_extensions(&self) -> Option<&Extension> {
        self.get_extension(ExtensionType::OuterExtensions)
    }

    pub fn sni(&self) -> String {
        let ext = match self.get_extension(ExtensionType::ServerName) {
            Some(ext) => ext,
            None => return String::new(),
        };
        let mut rd = Reader::from(ext.payload());
        let _ = rd.get_u16() as usize;
        let _ = rd.get_u8();
        let len = rd.get_u16() as usize;
        let sni = rd.read(len);
        String::from_utf8(sni.to_vec()).unwrap_or_default()
    }

    pub fn reconstruct(&self, outer: &ClientHello) -> Vec<u8> {
        let mut raw = Vec::with_capacity(outer.raw.len());
        raw.extend_from_slice(&self.version.to_be_bytes());
        raw.extend_from_slice(self.random);
        raw.extend_from_slice(outer.session);
        raw.extend_from_slice(self.cipher_suites);
        raw.extend_from_slice(self.compressions);
        let extension_len_off = raw.len();
        raw.extend_from_slice(&[0, 0]); // extensions length

        self.extensions.iter().for_each(|e| {
            if e.typ() == ExtensionType::OuterExtensions {
                let outer_extensions = self.outer_extensions().unwrap();
                let outer_extensions = ECHOuterExtensions::from(outer_extensions.payload());
                outer_extensions.extensions.iter().for_each(|typ| {
                    let e = outer.get_extension(*typ).unwrap();
                    raw.extend_from_slice(e.raw());
                });
            } else {
                raw.extend_from_slice(e.raw());
            }
        });

        // fix extensions length
        let extensions_length = (raw.len() - extension_len_off - 2) as u16;
        raw[extension_len_off..extension_len_off + 2]
            .copy_from_slice(&extensions_length.to_be_bytes());
        raw
    }
}

impl<'a> TryFrom<&'a [u8]> for ClientHello<'a> {
    type Error = TLSError;
    fn try_from(raw: &'a [u8]) -> Result<Self, Self::Error> {
        let mut rd = Reader::from(raw);
        let version = rd.get_u16();
        let random = rd.read(32);
        let session = rd.read8();
        let cipher_suites = rd.read16();
        let compressions = rd.read8();

        let ext_len = rd.get_u16() as usize;
        let ext_raw = rd.read(ext_len);
        let mut ext_rd = Reader::from(ext_raw);

        let mut extensions = Vec::new();
        // let mut cursor_len = 0;
        while !ext_rd.is_empty() {
            extensions.push(Extension::from(ext_rd.read16_at(2)));
        }

        // assert_eq!(cursor + ext_cursor, raw.len());
        Ok(Self {
            version,
            random,
            session,
            cipher_suites,
            compressions,
            extensions,
            raw,
        })
    }
}

impl std::fmt::Debug for ClientHello<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ClientHello")?;
        writeln!(f, "  version: {:?}", self.version)?;
        writeln!(f, "  random: {:?}", self.random)?;
        writeln!(f, "  session: {:?}", self.session)?;
        writeln!(f, "  cipher_suites: {:?}", self.cipher_suites)?;
        writeln!(f, "  compressions: {:?}", self.compressions)?;
        writeln!(f, "  extensions:")?;
        for extension in &self.extensions {
            writeln!(f, "    {:?}", extension)?;
        }
        Ok(())
    }
}

// type HpkeKemId = u16;
type HpkeKdfId = u16;
type HpkeAeadId = u16;

#[derive(Debug)]
pub struct HpkeSymmetricCipherSuite {
    pub kdf_id: HpkeKdfId,
    pub aead_id: HpkeAeadId,
}

#[derive(Debug, PartialEq)]
pub enum ECHClientHelloType {
    Outer = 0,
    Inner = 1,
}

impl TryFrom<u8> for ECHClientHelloType {
    type Error = TLSError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ECHClientHelloType::Outer),
            1 => Ok(ECHClientHelloType::Inner),
            invalid => Err(TLSError::InvalidECHClientHelloType(invalid)),
        }
    }
}

/// ECHClientHello
#[derive(Debug)]
pub struct ECHClientHello<'a> {
    pub cipher_suite: HpkeSymmetricCipherSuite,
    pub config_id: u8,
    pub enc: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for ECHClientHello<'a> {
    type Error = TLSError;
    fn try_from(raw: &'a [u8]) -> Result<Self, Self::Error> {
        let mut rd = Reader::from(raw);
        let typ: ECHClientHelloType = rd.get_u8().try_into()?;

        if typ == ECHClientHelloType::Inner {
            return Err(TLSError::InvalidECHClientHelloType(typ as u8));
        }
        let cipher_suite = HpkeSymmetricCipherSuite {
            kdf_id: rd.get_u16(),
            aead_id: rd.get_u16(),
        };
        let config_id = rd.get_u8();
        let len = rd.get_u16() as usize;
        let enc = rd.read(len);
        let len = rd.get_u16() as usize;
        let payload = rd.read(len);
        Ok(Self {
            cipher_suite,
            config_id,
            enc,
            payload,
        })
    }
}

#[derive(Debug)]
pub struct ECHOuterExtensions {
    pub extensions: Vec<ExtensionType>,
}

impl From<&[u8]> for ECHOuterExtensions {
    fn from(raw: &[u8]) -> Self {
        let length = raw[0] as usize;
        let extensions = &raw[1..length + 1];

        Self {
            extensions: extensions
                .chunks(2)
                .map(|chunk| [chunk[0], chunk[1]].into())
                .collect(),
        }
    }
}
