//! Lossless Windows self-relative security descriptors. No access decision is inferred.
use crate::{Error, Result, wire::*};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ace {
    pub kind: u8,
    pub flags: u8,
    pub access_mask: Option<u32>,
    pub sid: Option<String>,
    pub raw: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acl {
    pub revision: u8,
    pub aces: Vec<Ace>,
    pub raw: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDescriptor {
    pub control: u16,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub dacl_present: bool,
    pub sacl_present: bool,
    pub dacl: Option<Acl>,
    pub sacl: Option<Acl>,
    pub raw: Vec<u8>,
}
pub fn sid(data: &[u8]) -> Result<String> {
    let h = bytes(data, 0, 8)?;
    if h[0] != 1 || h[1] > 15 {
        return Err(corrupt("SID", 0, "invalid revision/subauthority count"));
    }
    let mut authority = 0u64;
    for b in &h[2..8] {
        authority = (authority << 8) | u64::from(*b);
    }
    let mut s = format!("S-1-{authority}");
    for i in 0..usize::from(h[1]) {
        s.push_str(&format!("-{}", u32le(data, 8 + i * 4)?));
    }
    Ok(s)
}
fn acl(data: &[u8]) -> Result<Acl> {
    let h = bytes(data, 0, 8)?;
    if ![2, 4].contains(&h[0]) {
        return Err(Error::Unsupported("Windows ACL revision".into()));
    }
    let size = usize::from(u16le(h, 2)?);
    let data = bytes(data, 0, size)?;
    let count = usize::from(u16le(h, 4)?);
    if size < 8 || count > 4096 {
        return Err(corrupt("ACL", 0, "invalid ACL size/count"));
    }
    let mut at = 8;
    let mut aces = Vec::with_capacity(count);
    for _ in 0..count {
        let size = usize::from(u16le(data, at + 2)?);
        if size < 4 || !size.is_multiple_of(4) {
            return Err(corrupt("ACL", at as u64, "invalid ACE size"));
        }
        let raw = bytes(data, at, size)?;
        let kind = raw[0];
        let sid_at = match kind {
            0..=3 | 9 | 10 | 13 | 14 | 17..=21 => Some(8),
            5..=8 | 11 | 12 | 15 | 16 => {
                let flags = u32le(raw, 8)?;
                if flags & !3 != 0 {
                    return Err(corrupt("ACE", at as u64, "unknown object flags"));
                }
                Some(12 + if flags & 1 != 0 { 16 } else { 0 } + if flags & 2 != 0 { 16 } else { 0 })
            }
            _ => None,
        };
        let (mask, sid) = if let Some(offset) = sid_at {
            (
                Some(u32le(raw, 4)?),
                Some(sid(bytes(
                    raw,
                    offset,
                    raw.len()
                        .checked_sub(offset)
                        .ok_or_else(|| corrupt("ACE", at as u64, "short ACE"))?,
                )?)?),
            )
        } else {
            (None, None)
        };
        aces.push(Ace {
            kind,
            flags: raw[1],
            access_mask: mask,
            sid,
            raw: raw.to_vec(),
        });
        at += size;
    }
    Ok(Acl {
        revision: h[0],
        aces,
        raw: data.to_vec(),
    })
}
pub fn parse(data: &[u8]) -> Result<SecurityDescriptor> {
    let h = bytes(data, 0, 20)?;
    let control = u16le(h, 2)?;
    if h[0] != 1 || control & 0x8000 == 0 {
        return Err(Error::Unsupported(
            "non-self-relative Windows security descriptor".into(),
        ));
    }
    let component = |field: usize| -> Result<Option<&[u8]>> {
        let offset = u32le(h, field)? as usize;
        if offset == 0 {
            Ok(None)
        } else if offset < 20 || !offset.is_multiple_of(4) {
            Err(corrupt(
                "security descriptor",
                offset as u64,
                "invalid relative offset",
            ))
        } else {
            Ok(Some(bytes(
                data,
                offset,
                data.len().checked_sub(offset).ok_or_else(|| {
                    corrupt("security descriptor", offset as u64, "outside descriptor")
                })?,
            )?))
        }
    };
    if control & 4 == 0 && u32le(h, 16)? != 0 || control & 0x10 == 0 && u32le(h, 12)? != 0 {
        return Err(corrupt(
            "security descriptor",
            0,
            "ACL offset without presence flag",
        ));
    }
    Ok(SecurityDescriptor {
        control,
        owner: component(4)?.map(sid).transpose()?,
        group: component(8)?.map(sid).transpose()?,
        dacl_present: control & 4 != 0,
        sacl_present: control & 0x10 != 0,
        dacl: component(16)?.map(acl).transpose()?,
        sacl: component(12)?.map(acl).transpose()?,
        raw: data.to_vec(),
    })
}
pub fn ntfs_hash(data: &[u8]) -> u32 {
    data.chunks(4).fold(0u32, |hash, chunk| {
        let mut word = [0; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        hash.rotate_left(3).wrapping_add(u32::from_le_bytes(word))
    })
}
