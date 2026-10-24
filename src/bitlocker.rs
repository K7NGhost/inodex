//! Read-only BitLocker v2 volume view. Keys are supplied explicitly; no guessing.
use crate::{
    Error, Result,
    image::{DiskImage, read_vec},
    wire::*,
};
use aes::{
    Aes128, Aes256,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use ccm::{
    Ccm,
    aead::AeadInPlace,
    consts::{U12, U16},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub enum Credential<'a> {
    Password(&'a str),
    RecoveryPassword(&'a str),
    Vmk(&'a [u8]),
    Fvek(&'a [u8]),
    ClearKey,
}
#[derive(Debug, Clone, Serialize)]
pub struct Info {
    pub method: u16,
    pub sector_size: u32,
    pub encrypted_bytes: u64,
    pub header_offset: u64,
    pub header_bytes: u64,
    pub metadata_offsets: [u64; 3],
    pub metadata_version: u16,
}
enum AesKey {
    Small(Box<Aes128>),
    Large(Box<Aes256>),
}
impl AesKey {
    fn new(key: &[u8]) -> Result<Self> {
        match key.len() {
            16 => Ok(Self::Small(Box::new(Aes128::new_from_slice(key).unwrap()))),
            32 => Ok(Self::Large(Box::new(Aes256::new_from_slice(key).unwrap()))),
            _ => Err(Error::Unsupported("BitLocker AES key length".into())),
        }
    }
    fn encrypt(&self, block: &mut [u8; 16]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            Self::Small(k) => k.encrypt_block(block),
            Self::Large(k) => k.encrypt_block(block),
        }
    }
    fn decrypt(&self, block: &mut [u8; 16]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            Self::Small(k) => k.decrypt_block(block),
            Self::Large(k) => k.decrypt_block(block),
        }
    }
}
struct Cipher {
    method: u16,
    data: AesKey,
    tweak: Option<AesKey>,
}
impl Cipher {
    fn new(method: u16, key: &[u8]) -> Result<Self> {
        let (a, b) = match method {
            0x8000 | 0x8001 => {
                if key.len() != 64 {
                    return Err(Error::Unsupported(
                        "BitLocker diffuser FVEK requires 64 bytes".into(),
                    ));
                }
                let n = if method == 0x8000 { 16 } else { 32 };
                (&key[..n], Some(&key[32..32 + n]))
            }
            0x8002 if key.len() == 16 => (key, None),
            0x8003 if key.len() == 32 => (key, None),
            0x8004 if key.len() == 32 => (&key[..16], Some(&key[16..])),
            0x8005 if key.len() == 64 => (&key[..32], Some(&key[32..])),
            _ => {
                return Err(Error::Unsupported(
                    "BitLocker encryption method/FVEK length".into(),
                ));
            }
        };
        Ok(Self {
            method,
            data: AesKey::new(a)?,
            tweak: b.map(AesKey::new).transpose()?,
        })
    }
    fn decrypt(&self, data: &mut [u8], physical: u64, sector: u64) {
        let mut iv = [0; 16];
        iv[..8].copy_from_slice(
            &(if self.method >= 0x8004 {
                physical / sector
            } else {
                physical
            })
            .to_le_bytes(),
        );
        if self.method >= 0x8004 {
            self.tweak.as_ref().unwrap().encrypt(&mut iv);
            for chunk in data.as_chunks_mut::<16>().0 {
                let mut block = *chunk;
                for i in 0..16 {
                    block[i] ^= iv[i];
                }
                self.data.decrypt(&mut block);
                for i in 0..16 {
                    chunk[i] = block[i] ^ iv[i];
                }
                let mut carry = 0;
                for value in &mut iv {
                    let next = *value >> 7;
                    *value = (*value << 1) | carry;
                    carry = next;
                }
                if carry != 0 {
                    iv[0] ^= 0x87;
                }
            }
        } else {
            self.data.encrypt(&mut iv);
            for chunk in data.as_chunks_mut::<16>().0 {
                let original = *chunk;
                let mut block = original;
                self.data.decrypt(&mut block);
                for i in 0..16 {
                    chunk[i] = block[i] ^ iv[i];
                }
                iv = original;
            }
            if self.method <= 0x8001 {
                let mut words = Zeroizing::new(
                    data.as_chunks::<4>()
                        .0
                        .iter()
                        .map(|v| u32::from_le_bytes(*v))
                        .collect::<Vec<_>>(),
                );
                let n = words.len();
                for (rounds, delta, rotations) in [(3, 1, [0, 10, 0, 25]), (5, -1, [9, 0, 13, 0])] {
                    for _ in 0..rounds {
                        for i in 0..n {
                            let index = |by: isize| -> usize {
                                (i as isize + delta * by).rem_euclid(n as isize) as usize
                            };
                            words[i] = words[i].wrapping_add(
                                words[index(2)] ^ words[index(5)].rotate_left(rotations[i % 4]),
                            );
                        }
                    }
                }
                let mut tweak = [0; 16];
                tweak[..8].copy_from_slice(&physical.to_le_bytes());
                let mut k1 = tweak;
                self.tweak.as_ref().unwrap().encrypt(&mut k1);
                tweak[15] = 0x80;
                let mut k2 = tweak;
                self.tweak.as_ref().unwrap().encrypt(&mut k2);
                for (i, word) in words.iter().enumerate() {
                    data[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
                for (i, b) in data.iter_mut().enumerate() {
                    *b ^= if i % 32 < 16 { k1[i % 16] } else { k2[i % 16] };
                }
            }
        }
    }
}
fn entries(data: &[u8]) -> Result<Vec<(u16, u16, &[u8])>> {
    let mut result = vec![];
    let mut at = 0;
    while at < data.len() {
        if data[at..].iter().all(|b| *b == 0) {
            break;
        }
        let size = usize::from(u16le(data, at)?);
        if size < 8 || result.len() >= 4096 {
            return Err(corrupt(
                "BitLocker metadata",
                at as u64,
                "invalid entry size/count",
            ));
        }
        let entry = bytes(data, at, size)?;
        if ![1, 3].contains(&u16le(entry, 6)?) {
            return Err(Error::Unsupported(
                "BitLocker metadata entry version".into(),
            ));
        }
        result.push((u16le(entry, 2)?, u16le(entry, 4)?, &entry[8..]));
        at += size;
    }
    Ok(result)
}
fn unlock_ccm(data: &[u8], key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    type AesCcm = Ccm<Aes256, U16, U12>;
    let nonce = bytes(data, 0, 12)?;
    let tag = bytes(data, 12, 16)?;
    let mut plain = Zeroizing::new(
        bytes(
            data,
            28,
            data.len()
                .checked_sub(28)
                .ok_or_else(|| corrupt("BitLocker key", 0, "short CCM blob"))?,
        )?
        .to_vec(),
    );
    AesCcm::new_from_slice(key)
        .map_err(|_| Error::Unsupported("BitLocker VMK/protector key length".into()))?
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            b"",
            &mut plain,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| Error::Unsupported("BitLocker credential authentication failed".into()))?;
    if u32le(&plain, 0)? as usize != plain.len() || u16le(&plain, 4)? != 1 || plain.len() < 12 {
        return Err(corrupt("BitLocker key", 0, "decrypted key header"));
    }
    Ok(plain)
}
fn stretch(initial: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut state = Zeroizing::new([0; 88]);
    state[32..64].copy_from_slice(initial);
    state[64..80].copy_from_slice(salt);
    for count in 0..0x100000u64 {
        state[80..].copy_from_slice(&count.to_le_bytes());
        let hash = Sha256::digest(&state[..]);
        state[..32].copy_from_slice(&hash);
    }
    let mut output = Zeroizing::new([0; 32]);
    output.copy_from_slice(&state[..32]);
    output
}
fn recovery_initial(password: &str) -> Result<Zeroizing<[u8; 32]>> {
    let parts: Vec<_> = password.split('-').collect();
    if parts.len() != 8 {
        return Err(Error::Unsupported(
            "BitLocker recovery password requires eight groups".into(),
        ));
    }
    let mut key = Zeroizing::new([0; 16]);
    for (i, part) in parts.iter().enumerate() {
        if part.len() != 6 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Unsupported(
                "invalid BitLocker recovery password group".into(),
            ));
        }
        let n: u32 = part
            .parse()
            .map_err(|_| Error::Unsupported("invalid recovery password".into()))?;
        if !n.is_multiple_of(11) || n / 11 > 65535 {
            return Err(Error::Unsupported(
                "invalid BitLocker recovery password checksum/range".into(),
            ));
        }
        key[i * 2..i * 2 + 2].copy_from_slice(&((n / 11) as u16).to_le_bytes());
    }
    let mut initial = Zeroizing::new([0; 32]);
    initial.copy_from_slice(&Sha256::digest(&key[..]));
    Ok(initial)
}
fn fvek(data: &[u8], credential: Credential<'_>, method: u16) -> Result<Zeroizing<Vec<u8>>> {
    if let Credential::Fvek(key) = credential {
        Cipher::new(method, key)?;
        return Ok(Zeroizing::new(key.to_vec()));
    }
    let all = entries(data)?;
    let vmk = if let Credential::Vmk(key) = credential {
        if key.len() != 32 {
            return Err(Error::Unsupported("BitLocker VMK must be 32 bytes".into()));
        }
        Zeroizing::new(key.to_vec())
    } else {
        let mut initial = None;
        match credential {
            Credential::Password(password) => {
                if password.len() > 4096 {
                    return Err(Error::ResourceLimit("BitLocker password length"));
                }
                let encoded = Zeroizing::new(
                    password
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect::<Vec<_>>(),
                );
                let hash = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(&encoded[..])));
                initial = Some(Zeroizing::new(<[u8; 32]>::from(Sha256::digest(&hash[..]))));
            }
            Credential::RecoveryPassword(password) => initial = Some(recovery_initial(password)?),
            Credential::ClearKey => {}
            _ => unreachable!(),
        }
        let mut found = None;
        let mut attempts = 0;
        for (kind, value, payload) in &all {
            if *kind != 2 || *value != 8 {
                continue;
            }
            let protection = u16le(payload, 26)?;
            let matches = match credential {
                Credential::Password(_) => protection == 0x2000,
                Credential::RecoveryPassword(_) => protection == 0x800,
                Credential::ClearKey => protection == 0,
                _ => false,
            };
            if !matches {
                continue;
            }
            attempts += 1;
            if attempts > 8 {
                return Err(Error::ResourceLimit("BitLocker key protector attempts"));
            }
            let props = entries(bytes(
                payload,
                28,
                payload
                    .len()
                    .checked_sub(28)
                    .ok_or_else(|| corrupt("BitLocker VMK", 0, "short protector"))?,
            )?)?;
            let key = if let Some(initial) = &initial {
                let salt = props
                    .iter()
                    .find(|(_, v, _)| *v == 3)
                    .ok_or_else(|| corrupt("BitLocker VMK", 0, "missing stretch key"))?
                    .2;
                Zeroizing::new(stretch(&initial[..], bytes(salt, 4, 16)?).to_vec())
            } else {
                let raw = props
                    .iter()
                    .find(|(_, v, _)| *v == 1)
                    .ok_or_else(|| corrupt("BitLocker VMK", 0, "missing clear key"))?
                    .2;
                Zeroizing::new(bytes(raw, 4, 32)?.to_vec())
            };
            let sealed = props
                .iter()
                .find(|(_, v, _)| *v == 5)
                .ok_or_else(|| corrupt("BitLocker VMK", 0, "missing encrypted VMK"))?
                .2;
            if let Ok(plain) = unlock_ccm(sealed, &key) {
                if plain.len() != 44 {
                    return Err(corrupt("BitLocker VMK", 0, "invalid VMK size"));
                }
                found = Some(Zeroizing::new(plain[12..].to_vec()));
                break;
            }
        }
        found.ok_or_else(|| {
            Error::Unsupported(
                "BitLocker credential could not authenticate a matching protector".into(),
            )
        })?
    };
    let encrypted = all
        .iter()
        .find(|(kind, value, _)| *kind == 3 && *value == 5)
        .ok_or_else(|| corrupt("BitLocker", 0, "missing encrypted FVEK"))?
        .2;
    let plain = unlock_ccm(encrypted, &vmk)?;
    if u16le(&plain, 8)? != method {
        return Err(corrupt("BitLocker FVEK", 0, "encryption method mismatch"));
    }
    Ok(Zeroizing::new(plain[12..].to_vec()))
}
pub struct BitLocker<'a> {
    image: &'a mut dyn DiskImage,
    info: Info,
    cipher: Cipher,
    size: u64,
    cache: Option<(u64, Zeroizing<Vec<u8>>)>,
    metadata_size: u64,
}
impl<'a> BitLocker<'a> {
    pub fn open(image: &'a mut dyn DiskImage, credential: Credential<'_>) -> Result<Self> {
        let boot = read_vec(image, 0, 512)?;
        let to_go = &boot[3..11] == b"MSWIN4.1";
        let identifier = [
            0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3,
            0xd0, 0x01,
        ];
        if boot[if to_go { 424 } else { 160 }..if to_go { 440 } else { 176 }] != identifier {
            return Err(Error::Unsupported(
                "BitLocker Vista/used-space-only/unknown volume identifier".into(),
            ));
        }
        if &boot[3..11] != b"-FVE-FS-" && !to_go {
            return Err(Error::Unsupported(
                "not a supported BitLocker volume header".into(),
            ));
        }
        let sector = u32::from(u16le(&boot, 11)?);
        if ![512, 4096].contains(&sector) {
            return Err(Error::Unsupported("BitLocker sector size".into()));
        }
        if !image.len().is_multiple_of(u64::from(sector)) {
            return Err(corrupt(
                "BitLocker",
                0,
                "truncated/non-sector-aligned volume",
            ));
        }
        let base = if to_go { 440 } else { 176 };
        let offsets = [
            u64le(&boot, base)?,
            u64le(&boot, base + 8)?,
            u64le(&boot, base + 16)?,
        ];
        if offsets[0] == offsets[1] || offsets[0] == offsets[2] || offsets[1] == offsets[2] {
            return Err(corrupt("BitLocker", 0, "duplicate metadata offsets"));
        }
        let mut chosen = None;
        for at in offsets {
            checked_region(at, 65536, image.len(), "BitLocker metadata reservation")?;
            if at < 512 || !at.is_multiple_of(u64::from(sector)) {
                return Err(corrupt("BitLocker", at, "metadata offset"));
            }
            let header = read_vec(image, at, 112)?;
            if &header[..8] != b"-FVE-FS-" || u16le(&header, 10)? != 2 {
                return Err(Error::Unsupported(
                    "BitLocker metadata version (requires Windows 7 or later)".into(),
                ));
            }
            if u16le(&header, 12)? != 4 || u16le(&header, 14)? != 4 {
                return Err(Error::Unsupported(
                    "BitLocker conversion/suspended encryption state".into(),
                ));
            }
            if [
                u64le(&header, 32)?,
                u64le(&header, 40)?,
                u64le(&header, 48)?,
            ] != offsets
            {
                return Err(corrupt("BitLocker", at, "metadata locations disagree"));
            }
            let length = u32le(&header, 64)? as usize;
            if !(48..=16 * 1024 * 1024).contains(&length)
                || u32le(&header, 68)? != 1
                || u32le(&header, 72)? != 48
                || u32le(&header, 76)? as usize != length
            {
                return Err(corrupt("BitLocker", at, "metadata length/version"));
            }
            let method = u16le(&header, 100)?;
            let header_offset = u64le(&header, 56)?;
            let encrypted = u64le(&header, 16)?;
            let header_size = u64::from(u32le(&header, 28)?) * u64::from(sector);
            checked_region(0, encrypted, image.len(), "BitLocker encrypted volume")?;
            checked_region(
                header_offset,
                header_size,
                image.len(),
                "BitLocker relocated header",
            )?;
            if !header_offset.is_multiple_of(u64::from(sector))
                || header_size == 0
                || !encrypted.is_multiple_of(u64::from(sector))
            {
                return Err(corrupt("BitLocker", at, "unaligned/empty geometry"));
            }
            let data = read_vec(image, at + 64, length)?;
            if chosen.is_none() {
                chosen = Some((header, data, method, header_offset, header_size, encrypted));
            } else if let Some((first, _, m, h, s, e)) = &chosen
                && (*m != method
                    || *h != header_offset
                    || *s != header_size
                    || *e != encrypted
                    || first[80..96] != data[16..32])
            {
                return Err(corrupt(
                    "BitLocker",
                    at,
                    "metadata copies disagree on volume geometry/identity",
                ));
            }
        }
        let (_, data, method, header_offset, mut header_bytes, encrypted_bytes) = chosen.unwrap();
        for (kind, value, payload) in entries(&data[48..])? {
            if kind == 15 && value == 15 {
                if u64le(payload, 0)? != header_offset {
                    return Err(corrupt("BitLocker", 0, "header descriptor disagrees"));
                }
                header_bytes = u64le(payload, 8)?;
            }
        }
        checked_region(header_offset, header_bytes, image.len(), "BitLocker header")?;
        if header_bytes == 0
            || !header_bytes.is_multiple_of(u64::from(sector))
            || header_offset < header_bytes
        {
            return Err(corrupt(
                "BitLocker",
                header_offset,
                "invalid relocated header geometry",
            ));
        }
        checked_region(
            header_offset,
            header_bytes,
            encrypted_bytes,
            "BitLocker encrypted header",
        )?;
        let mut reserved = offsets.map(|at| (at, at + 65536)).to_vec();
        reserved.push((header_offset, header_offset + header_bytes));
        reserved.sort_unstable();
        if reserved.windows(2).any(|w| w[0].1 > w[1].0) {
            return Err(corrupt(
                "BitLocker",
                0,
                "overlapping metadata/header reservations",
            ));
        }
        let key = fvek(&data[48..], credential, method)?;
        let cipher = Cipher::new(method, &key)?;
        let size = image.len();
        let mut result = Self {
            image,
            info: Info {
                method,
                sector_size: sector,
                encrypted_bytes,
                header_offset,
                header_bytes,
                metadata_offsets: offsets,
                metadata_version: 2,
            },
            cipher,
            size,
            cache: None,
            metadata_size: 65536,
        };
        let mut plain = [0; 512];
        result.read_exact_at(0, &mut plain)?;
        if plain[510..] != [0x55, 0xaa]
            || &plain[3..11] != b"NTFS    " && !(plain[0] == 0xeb || plain[0] == 0xe9)
        {
            return Err(corrupt(
                "BitLocker",
                0,
                "decrypted boot record validation failed",
            ));
        }
        Ok(result)
    }
    pub fn info(&self) -> &Info {
        &self.info
    }
}
impl DiskImage for BitLocker<'_> {
    fn len(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u32 {
        self.info.sector_size
    }
    fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<usize> {
        let n = self.size.saturating_sub(offset).min(out.len() as u64) as usize;
        let sector = u64::from(self.info.sector_size);
        let mut done = 0;
        while done < n {
            let at = offset + done as u64;
            let start = at / sector * sector;
            if self.cache.as_ref().is_none_or(|(at, _)| *at != start) {
                let mut data = Zeroizing::new(vec![0; sector as usize]);
                let reserved = self
                    .info
                    .metadata_offsets
                    .iter()
                    .any(|m| start >= *m && start - *m < self.metadata_size)
                    || start >= self.info.header_offset
                        && start - self.info.header_offset < self.info.header_bytes;
                if !reserved {
                    let physical = if start < self.info.header_bytes {
                        self.info.header_offset + start
                    } else {
                        start
                    };
                    self.image.read_exact_at(physical, &mut data)?;
                    if physical < self.info.encrypted_bytes {
                        self.cipher.decrypt(&mut data, physical, sector);
                    }
                }
                self.cache = Some((start, data));
            }
            let within = (at - start) as usize;
            let count = (n - done).min(sector as usize - within);
            out[done..done + count]
                .copy_from_slice(&self.cache.as_ref().unwrap().1[within..within + count]);
            done += count;
        }
        Ok(n)
    }
}
