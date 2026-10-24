//! Bounded MS-XCA LZNT1 decoder. Each chunk has its own 4096-byte history.
use crate::{
    Result,
    wire::{bytes, corrupt, u16le},
};

pub fn decompress(input: &[u8], maximum: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if maximum > 16 * 1024 * 1024 {
        return Err(crate::Error::ResourceLimit("LZNT1 decoded buffer"));
    }
    out.try_reserve_exact(maximum)
        .map_err(|_| crate::Error::ResourceLimit("LZNT1 decoded allocation"))?;
    let mut at = 0;
    while at < input.len() {
        if input.len() - at == 1 && input[at] == 0 {
            break;
        }
        let header = u16le(input, at)?;
        at += 2;
        if header == 0 {
            if input[at..].iter().any(|b| *b != 0) {
                return Err(corrupt("LZNT1", at as u64, "nonzero data after terminator"));
            }
            break;
        }
        if header & 0x7000 != 0x3000 {
            return Err(corrupt("LZNT1", at as u64, "invalid chunk signature"));
        }
        let n = usize::from(header & 0xfff) + 1;
        let chunk = bytes(input, at, n)?;
        at += n;
        let start = out.len();
        if header & 0x8000 == 0 {
            if n > maximum.saturating_sub(out.len()) {
                return Err(corrupt("LZNT1", at as u64, "decoded size exceeds unit"));
            }
            out.extend_from_slice(chunk);
        } else {
            let mut pos = 0;
            while pos < chunk.len() {
                let flags = chunk[pos];
                pos += 1;
                for bit in 0..8 {
                    if pos == chunk.len() {
                        break;
                    }
                    if flags & (1 << bit) == 0 {
                        if out.len() - start >= 4096 || out.len() >= maximum {
                            return Err(corrupt("LZNT1", at as u64, "literal exceeds chunk/unit"));
                        }
                        out.push(chunk[pos]);
                        pos += 1;
                    } else {
                        let token = u16le(chunk, pos)?;
                        pos += 2;
                        let mut mask = 0xfffu16;
                        let mut shift = 12;
                        let mut distance = out.len() - start;
                        while distance > 16 {
                            mask >>= 1;
                            shift -= 1;
                            distance = distance.div_ceil(2);
                        }
                        let length = usize::from(token & mask) + 3;
                        let back = usize::from(token >> shift) + 1;
                        if back > out.len() - start
                            || length > 4096 - (out.len() - start)
                            || length > maximum.saturating_sub(out.len())
                        {
                            return Err(corrupt(
                                "LZNT1",
                                at as u64,
                                "invalid back reference or decoded length",
                            ));
                        }
                        for _ in 0..length {
                            out.push(out[out.len() - back]);
                        }
                    }
                }
            }
        }
        // Only a final logical chunk may be short.
        if out.len() - start < 4096 && at < input.len() && input[at..].iter().any(|b| *b != 0) {
            return Err(corrupt("LZNT1", at as u64, "short nonfinal chunk"));
        }
    }
    Ok(out)
}
