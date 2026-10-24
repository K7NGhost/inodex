mod layers_support;
use inodex::{
    bitlocker::{BitLocker, Credential},
    filesystem::FileSystem,
    image::DiskImage,
};
use layers_support::*;
use std::{fs, io::Read, path::Path};
fn fixture(name: &str) -> Vec<u8> {
    let mut out = vec![];
    flate2::read::GzDecoder::new(
        fs::File::open(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/forensics")
                .join(format!("{name}.gz")),
        )
        .unwrap(),
    )
    .read_to_end(&mut out)
    .unwrap();
    out
}
#[test]
fn public_windows_bitlocker_to_go_password_unlock_and_file_extraction() {
    let raw = fixture("bdetogo-selected.raw");
    let selection: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/forensics/bdetogo-selection.json")).unwrap();
    use sha2::{Digest, Sha256};
    assert_eq!(
        inodex::ewf::hex(&Sha256::digest(&raw)),
        selection["selected_sha256"].as_str().unwrap()
    );
    let mut image = Memory::new(raw);
    let mut volume = BitLocker::open(&mut image, Credential::Password("bde-TEST")).unwrap();
    assert_eq!(volume.info().method, 0x8000);
    let mut boot = [0; 512];
    volume.read_exact_at(0, &mut boot).unwrap();
    assert_eq!(boot[510..], [0x55, 0xaa]);
    let mut fs = FileSystem::open(&mut volume).unwrap();
    let id = fs.resolve("/passwords.txt").unwrap();
    let mut out = vec![];
    fs.copy_file(id, None, &mut out).unwrap();
    assert_eq!(out.len(), 116);
    assert_eq!(
        inodex::ewf::hex(&Sha256::digest(out)),
        "02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252"
    );
}

#[test]
fn independently_encrypted_cbc_diffuser_and_xts_images_match_original_bytes() {
    use sha2::{Digest, Sha256};
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/forensics/bitlocker-generated.json")).unwrap();
    for (name, record) in manifest["records"].as_object().unwrap() {
        let data = fixture(name);
        assert_eq!(
            inodex::ewf::hex(&Sha256::digest(&data)),
            record["sha256"].as_str().unwrap()
        );
        let key = hex(record["key"].as_str().unwrap());
        let mut image = Memory::new(data);
        let mut volume = BitLocker::open(&mut image, Credential::Fvek(&key)).unwrap();
        let mut decoded = vec![0; volume.len() as usize];
        volume.read_exact_at(0, &mut decoded).unwrap();
        assert_eq!(
            inodex::ewf::hex(&Sha256::digest(&decoded)),
            record["decoded_sha256"].as_str().unwrap(),
            "{name}"
        );
        for offset in [
            0,
            1,
            511,
            512,
            8190,
            8192,
            848 * 4096 - 3,
            848 * 4096,
            960 * 4096,
            decoded.len() - 1,
            decoded.len(),
        ] {
            let mut out = [0xa5; 1027];
            let n = volume.read_at(offset as u64, &mut out).unwrap();
            let count = decoded.len().saturating_sub(offset).min(out.len());
            assert_eq!(n, count);
            assert_eq!(&out[..n], &decoded[offset..offset + n]);
            assert!(out[n..].iter().all(|b| *b == 0xa5));
        }
        assert_eq!(volume.read_at(u64::MAX, &mut [0; 16]).unwrap(), 0);
        let mut fs = FileSystem::open(&mut volume).unwrap();
        let id = fs.resolve("/passwords.txt").unwrap();
        let mut out = vec![];
        fs.copy_file(id, None, &mut out).unwrap();
        assert_eq!(out.len(), 116);
    }
}
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn bitlocker_recovery_vmk_and_clear_key_protectors_and_wrong_keys() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/forensics/bitlocker-generated.json")).unwrap();
    let vmk = hex(manifest["records"]["bitlocker-8004.raw"]["vmk"]
        .as_str()
        .unwrap());
    let data = fixture("bitlocker-8004.raw");
    for credential in [
        Credential::RecoveryPassword(manifest["recovery_password"].as_str().unwrap()),
        Credential::Vmk(&vmk),
        Credential::ClearKey,
    ] {
        let mut image = Memory::new(data.clone());
        let mut volume = BitLocker::open(&mut image, credential).unwrap();
        let mut boot = [0; 512];
        volume.read_exact_at(0, &mut boot).unwrap();
        assert_eq!(&boot[3..11], b"NTFS    ");
    }
    for credential in [
        Credential::Password("wrong"),
        Credential::RecoveryPassword("000001-000000-000000-000000-000000-000000-000000-000000"),
        Credential::Vmk(&[0; 32]),
        Credential::Fvek(&[0; 32]),
    ] {
        assert!(BitLocker::open(&mut Memory::new(data.clone()), credential).is_err());
    }
}

#[test]
fn malformed_bitlocker_metadata_states_geometry_and_authentication_fail() {
    let original = fixture("bitlocker-8004.raw");
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/forensics/bitlocker-generated.json")).unwrap();
    let key = hex(manifest["records"]["bitlocker-8004.raw"]["key"]
        .as_str()
        .unwrap());
    let meta = 848 * 4096;
    for (at, value) in [
        (11, 1),
        (160, 0),
        (meta, 0),
        (meta + 10, 1),
        (meta + 12, 5),
        (meta + 64, 0),
        (meta + 100, 0),
    ] {
        let mut data = original.clone();
        data[at] = value;
        assert!(
            BitLocker::open(&mut Memory::new(data), Credential::Fvek(&key)).is_err(),
            "offset {at}"
        );
    }
    for cut in [0, 511, meta + 111, original.len() - 1] {
        assert!(
            BitLocker::open(
                &mut Memory::new(original[..cut].to_vec()),
                Credential::Fvek(&key)
            )
            .is_err()
        );
    }
    let mut data = original.clone();
    data.copy_within(176..184, 184);
    assert!(BitLocker::open(&mut Memory::new(data), Credential::Fvek(&key)).is_err());
    let mut data = original;
    let length = u32::from_le_bytes(data[meta + 64..meta + 68].try_into().unwrap()) as usize;
    let mut at = meta + 112;
    while at < meta + 64 + length {
        let n = u16::from_le_bytes(data[at..at + 2].try_into().unwrap()) as usize;
        if u16::from_le_bytes(data[at + 2..at + 4].try_into().unwrap()) == 3 {
            data[at + 20] ^= 1;
            break;
        }
        at += n;
    }
    let vmk = hex(manifest["records"]["bitlocker-8004.raw"]["vmk"]
        .as_str()
        .unwrap());
    assert!(BitLocker::open(&mut Memory::new(data), Credential::Vmk(&vmk)).is_err());
}

#[test]
fn encrypted_volumes_require_explicit_unlock_instead_of_parsing_bait_fat() {
    for name in ["bitlocker-8004.raw", "bdetogo-selected.raw"] {
        assert!(
            matches!(FileSystem::open(&mut Memory::new(fixture(name))),Err(inodex::Error::Unsupported(message)) if message.contains("BitLocker"))
        );
    }
}
