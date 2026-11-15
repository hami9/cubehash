use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use cubehash_core::primitives::hmac_sha256_parts;
use cubehash_core::OsBoundHardwareProvider;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SealedKeyMaterial {
    device_secret: [u8; 32],
    ed25519_seed: [u8; 32],
    machine_guid: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct KeystoreDiskFile {
    version: u32,
    client_id: String,
    backend: String,
    ed25519_public_hex: String,
    sealed_blob_hex: String,
    #[serde(default)]
    trusted_peers: HashMap<String, String>,
}

/// Persistent or ephemeral device identity & hardware-backed secret store.
///
/// On Windows, seals the randomly generated CSPRNG `device_secret` and `Ed25519` signing key
/// at rest using Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`), probes TPM 2.0 CNG
/// availability (`Microsoft Platform Crypto Provider`), and binds execution to the Windows
/// Registry `MachineGuid` plus an optional `--hw-secret` passphrase factor.
/// Never falls back to deterministic username/id-derived secrets.
#[derive(Clone)]
pub struct DeviceIdentity {
    client_id: String,
    backend_label: String,
    signing_key: SigningKey,
    hw: OsBoundHardwareProvider,
    keystore_path: Option<PathBuf>,
    trusted_peers: HashMap<String, [u8; 32]>,
    sealed_blob_hex: String,
}

impl DeviceIdentity {
    /// Creates an ephemeral OS-CSPRNG identity in memory (suitable for automated tests).
    pub fn ephemeral_csprng(client_id: impl Into<String>) -> Result<Self, String> {
        let client_id = validate_client_id(&client_id.into())?;
        let mut device_secret = [0u8; 32];
        let mut ed_seed = [0u8; 32];
        getrandom::getrandom(&mut device_secret).map_err(|e| e.to_string())?;
        getrandom::getrandom(&mut ed_seed).map_err(|e| e.to_string())?;

        let signing_key = SigningKey::from_bytes(&ed_seed);
        let machine_id = detect_os_machine_id();
        let tpm = detect_tpm_cng();
        let hw = OsBoundHardwareProvider::from_host_and_secret_with_machine_id(
            &device_secret,
            client_id.as_bytes(),
            machine_id.as_deref().map(str::as_bytes),
        );

        device_secret.zeroize();
        ed_seed.zeroize();

        Ok(Self {
            client_id,
            backend_label: if tpm {
                "ephemeral-csprng+tpm2-cng".to_string()
            } else {
                "ephemeral-csprng".to_string()
            },
            signing_key,
            hw,
            keystore_path: None,
            trusted_peers: HashMap::new(),
            sealed_blob_hex: String::new(),
        })
    }

    /// Loads an existing OS-sealed identity from `keystore_dir` (or creates a new random
    /// identity sealed with Windows DPAPI on first run).
    ///
    /// If `passphrase` (`--hw-secret`) is supplied, it acts as a second factor mixed into both
    /// DPAPI additional entropy and hardware sealing derivation.
    pub fn load_or_create(
        client_id: impl Into<String>,
        keystore_dir: Option<&Path>,
        passphrase: Option<&str>,
    ) -> Result<Self, String> {
        let client_id = validate_client_id(&client_id.into())?;
        let base_dir = match keystore_dir {
            Some(d) => d.to_path_buf(),
            None => default_keystore_dir()?,
        };
        fs::create_dir_all(&base_dir)
            .map_err(|e| format!("failed to create keystore directory: {e}"))?;

        let safe_name = hex::encode(client_id.as_bytes());
        let file_path = base_dir.join(format!("{safe_name}.cubehash-id.json"));
        let machine_id = detect_os_machine_id();
        let tpm_available = detect_tpm_cng();
        let entropy = build_dpapi_entropy(&client_id, passphrase);

        if file_path.exists() {
            let raw = fs::read_to_string(&file_path)
                .map_err(|e| format!("failed to read keystore {}: {e}", file_path.display()))?;
            let disk: KeystoreDiskFile = serde_json::from_str(&raw)
                .map_err(|e| format!("corrupted keystore file: {e}"))?;
            if disk.client_id != client_id {
                return Err("keystore client_id mismatch".to_string());
            }

            let sealed_bytes = hex::decode(&disk.sealed_blob_hex)
                .map_err(|e| format!("invalid sealed keystore hex: {e}"))?;
            let mut plain_json = platform_unprotect(&sealed_bytes, &entropy)?;
            let mat: SealedKeyMaterial = serde_json::from_slice(&plain_json)
                .map_err(|_| "failed to parse unsealed keystore payload".to_string())?;
            plain_json.zeroize();

            if let (Some(expected_guid), Some(current_guid)) =
                (mat.machine_guid.as_deref(), machine_id.as_deref())
            {
                if expected_guid != current_guid {
                    return Err("hardware MachineGuid mismatch: keystore belongs to another device".to_string());
                }
            }

            let signing_key = SigningKey::from_bytes(&mat.ed25519_seed);
            let actual_pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
            if actual_pub_hex != disk.ed25519_public_hex {
                return Err("keystore Ed25519 public key integrity check failed".to_string());
            }

            let mut effective_secret =
                derive_effective_device_secret(&mat.device_secret, passphrase);
            let hw = OsBoundHardwareProvider::from_host_and_secret_with_machine_id(
                &effective_secret,
                client_id.as_bytes(),
                machine_id.as_deref().map(str::as_bytes),
            );
            effective_secret.zeroize();

            let mut trusted_peers = HashMap::new();
            for (peer, hex_pub) in disk.trusted_peers {
                if let Ok(bytes) = hex::decode(&hex_pub) {
                    if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                        trusted_peers.insert(peer, arr);
                    }
                }
            }

            return Ok(Self {
                client_id,
                backend_label: if tpm_available {
                    format!("{}+tpm2-cng", platform_backend_name())
                } else {
                    platform_backend_name().to_string()
                },
                signing_key,
                hw,
                keystore_path: Some(file_path),
                trusted_peers,
                sealed_blob_hex: disk.sealed_blob_hex,
            });
        }

        // First launch: generate fresh OS CSPRNG secrets and seal at rest via platform protection.
        let mut device_secret = [0u8; 32];
        let mut ed25519_seed = [0u8; 32];
        getrandom::getrandom(&mut device_secret).map_err(|e| e.to_string())?;
        getrandom::getrandom(&mut ed25519_seed).map_err(|e| e.to_string())?;

        let signing_key = SigningKey::from_bytes(&ed25519_seed);
        let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let mat = SealedKeyMaterial {
            device_secret,
            ed25519_seed,
            machine_guid: machine_id.clone(),
        };
        let mut mat_json = serde_json::to_vec(&mat).map_err(|e| e.to_string())?;
        let sealed_bytes = platform_protect(&mat_json, &entropy)?;
        mat_json.zeroize();

        let backend = if tpm_available {
            format!("{}+tpm2-cng", platform_backend_name())
        } else {
            platform_backend_name().to_string()
        };
        let sealed_blob_hex = hex::encode(&sealed_bytes);
        let disk = KeystoreDiskFile {
            version: 1,
            client_id: client_id.clone(),
            backend: backend.clone(),
            ed25519_public_hex: pub_hex,
            sealed_blob_hex: sealed_blob_hex.clone(),
            trusted_peers: HashMap::new(),
        };
        write_private_json(&file_path, &disk)?;

        let mut effective_secret = derive_effective_device_secret(&device_secret, passphrase);
        let hw = OsBoundHardwareProvider::from_host_and_secret_with_machine_id(
            &effective_secret,
            client_id.as_bytes(),
            machine_id.as_deref().map(str::as_bytes),
        );
        effective_secret.zeroize();
        device_secret.zeroize();
        ed25519_seed.zeroize();

        Ok(Self {
            client_id,
            backend_label: backend,
            signing_key,
            hw,
            keystore_path: Some(file_path),
            trusted_peers: HashMap::new(),
            sealed_blob_hex,
        })
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn backend_label(&self) -> &str {
        &self.backend_label
    }

    pub fn hardware_provider(&self) -> &OsBoundHardwareProvider {
        &self.hw
    }

    pub fn ed25519_pub(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn ed25519_pub_hex(&self) -> String {
        hex::encode(self.ed25519_pub())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub fn verify_signature(pub_bytes: &[u8; 32], message: &[u8], sig_bytes: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(pub_bytes) else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
        vk.verify_strict(message, &sig).is_ok()
    }

    /// Checks whether `peer_id`'s presented `Ed25519` public key matches the pinned key
    /// (pinning via TOFU if unseen), or rejects identity key changes as potential MITM.
    pub fn verify_or_pin_peer(&mut self, peer_id: &str, peer_pub: [u8; 32]) -> Result<(), String> {
        if let Some(pinned) = self.trusted_peers.get(peer_id) {
            if pinned != &peer_pub {
                return Err(format!(
                    "SECURITY ALERT: Ed25519 identity key for '{peer_id}' changed! Expected {}, got {}. Use /trust only if verified out-of-band.",
                    hex::encode(pinned),
                    hex::encode(peer_pub)
                ));
            }
            return Ok(());
        }
        self.trusted_peers.insert(peer_id.to_string(), peer_pub);
        self.persist_trusted_peers()
    }

    /// Explicitly pins/updates a trusted peer's Ed25519 public key after out-of-band verification.
    pub fn pin_peer_key(&mut self, peer_id: &str, peer_pub: [u8; 32]) -> Result<(), String> {
        let _ = VerifyingKey::from_bytes(&peer_pub)
            .map_err(|_| "invalid Ed25519 public key".to_string())?;
        self.trusted_peers.insert(peer_id.to_string(), peer_pub);
        self.persist_trusted_peers()
    }

    pub fn trusted_peer_key(&self, peer_id: &str) -> Option<[u8; 32]> {
        self.trusted_peers.get(peer_id).copied()
    }

    fn persist_trusted_peers(&self) -> Result<(), String> {
        let Some(path) = &self.keystore_path else {
            return Ok(());
        };
        let trusted_hex = self
            .trusted_peers
            .iter()
            .map(|(k, v)| (k.clone(), hex::encode(v)))
            .collect();
        let disk = KeystoreDiskFile {
            version: 1,
            client_id: self.client_id.clone(),
            backend: self.backend_label.clone(),
            ed25519_public_hex: self.ed25519_pub_hex(),
            sealed_blob_hex: self.sealed_blob_hex.clone(),
            trusted_peers: trusted_hex,
        };
        write_private_json(path, &disk)
    }
}

fn validate_client_id(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err("client_id must be 1..=64 characters".to_string());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err("client_id may only contain ASCII alphanumeric, '_', '-', or '.'".to_string());
    }
    if trimmed.contains("..") {
        return Err("client_id cannot contain '..'".to_string());
    }
    Ok(trimmed.to_string())
}

fn derive_effective_device_secret(device_secret: &[u8; 32], passphrase: Option<&str>) -> [u8; 32] {
    match passphrase.filter(|s| !s.is_empty()) {
        Some(pass) => hmac_sha256_parts(
            device_secret,
            &[b"cubehash-keystore-2fa-v1", pass.as_bytes()],
        ),
        None => *device_secret,
    }
}

fn build_dpapi_entropy(client_id: &str, passphrase: Option<&str>) -> Vec<u8> {
    let mut entropy = Vec::with_capacity(64);
    entropy.extend_from_slice(b"cubehash-dpapi-entropy-v1\0");
    entropy.extend_from_slice(client_id.as_bytes());
    if let Some(pass) = passphrase.filter(|s| !s.is_empty()) {
        entropy.push(0);
        entropy.extend_from_slice(pass.as_bytes());
    }
    entropy
}

fn default_keystore_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            return Ok(PathBuf::from(local_app_data).join("CubeHash").join("keystore"));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(xdg).join("cubehash").join("keystore"));
    }
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        return Ok(PathBuf::from(home).join(".cubehash").join("keystore"));
    }
    Err("unable to determine default keystore directory; pass --keystore-dir".to_string())
}

fn write_private_json(path: &Path, disk: &KeystoreDiskFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(disk).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| format!("failed to write keystore {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(windows)]
fn platform_backend_name() -> &'static str {
    "windows-dpapi"
}

#[cfg(not(windows))]
fn platform_backend_name() -> &'static str {
    "unix-host-bound"
}

#[cfg(windows)]
fn detect_os_machine_id() -> Option<String> {
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };

    let subkey: Vec<u16> = "SOFTWARE\\Microsoft\\Cryptography\0"
        .encode_utf16()
        .collect();
    let value_name: Vec<u16> = "MachineGuid\0".encode_utf16().collect();
    let mut hkey: HKEY = ptr::null_mut();
    // SAFETY: Valid null-terminated UTF-16 key string and output handle pointer.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }

    let mut data_type = 0u32;
    let mut byte_len = 256u32;
    let mut buf = vec![0u8; byte_len as usize];
    // SAFETY: Open HKEY with pre-allocated buffer; handle closed immediately after.
    let q_status = unsafe {
        RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            ptr::null_mut(),
            &mut data_type,
            buf.as_mut_ptr(),
            &mut byte_len,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }
    if q_status != ERROR_SUCCESS || data_type != REG_SZ || byte_len < 2 {
        return None;
    }
    let words_len = (byte_len as usize / 2).min(buf.len() / 2);
    let (chunks, _) = buf[..words_len * 2].as_chunks::<2>();
    let words: Vec<u16> = chunks
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .take_while(|&w| w != 0)
        .collect();
    let guid = String::from_utf16_lossy(&words);
    if guid.trim().is_empty() {
        None
    } else {
        Some(guid)
    }
}

#[cfg(not(windows))]
fn detect_os_machine_id() -> Option<String> {
    fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(windows)]
fn detect_tpm_cng() -> bool {
    use windows_sys::Win32::Security::Cryptography::{
        NCryptFreeObject, NCryptOpenStorageProvider, NCRYPT_HANDLE, NCRYPT_PROV_HANDLE,
    };
    let prov_name: Vec<u16> = "Microsoft Platform Crypto Provider\0"
        .encode_utf16()
        .collect();
    let mut prov: NCRYPT_PROV_HANDLE = 0;
    // SAFETY: Valid null-terminated provider name and output handle pointer.
    let status = unsafe { NCryptOpenStorageProvider(&mut prov, prov_name.as_ptr(), 0) };
    if status == 0 && prov != 0 {
        // SAFETY: Valid provider handle returned by NCryptOpenStorageProvider.
        unsafe {
            NCryptFreeObject(prov as NCRYPT_HANDLE);
        }
        true
    } else {
        false
    }
}

#[cfg(not(windows))]
fn detect_tpm_cng() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}

#[cfg(windows)]
fn platform_protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut pt = plaintext.to_vec();
    let mut ent = entropy.to_vec();
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: pt.len() as u32,
        pbData: pt.as_mut_ptr(),
    };
    let ent_blob = CRYPT_INTEGER_BLOB {
        cbData: ent.len() as u32,
        pbData: ent.as_mut_ptr(),
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    // SAFETY: Blobs point to live aligned buffers; out_blob.pbData is freed via LocalFree below.
    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            ptr::null(),
            &ent_blob,
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    pt.zeroize();
    ent.zeroize();

    if ok == 0 || out_blob.pbData.is_null() {
        return Err("Windows DPAPI CryptProtectData failed".to_string());
    }
    // SAFETY: out_blob.pbData is non-null and valid for out_blob.cbData bytes until LocalFree.
    let sealed = unsafe {
        std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
    };
    unsafe {
        LocalFree(out_blob.pbData as _);
    }
    Ok(sealed)
}

#[cfg(windows)]
fn platform_unprotect(ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut ct = ciphertext.to_vec();
    let mut ent = entropy.to_vec();
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: ct.len() as u32,
        pbData: ct.as_mut_ptr(),
    };
    let ent_blob = CRYPT_INTEGER_BLOB {
        cbData: ent.len() as u32,
        pbData: ent.as_mut_ptr(),
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    // SAFETY: Blobs point to live aligned buffers; out_blob.pbData is zeroized and freed via LocalFree.
    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            ptr::null_mut(),
            &ent_blob,
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    ct.zeroize();
    ent.zeroize();

    if ok == 0 || out_blob.pbData.is_null() {
        return Err("Windows DPAPI CryptUnprotectData rejected sealed keystore (wrong device/user/passphrase)".to_string());
    }
    // SAFETY: out_blob.pbData is valid for out_blob.cbData bytes; wipe OS buffer before LocalFree.
    let plain = unsafe {
        let slice = std::slice::from_raw_parts_mut(out_blob.pbData, out_blob.cbData as usize);
        let out = slice.to_vec();
        slice.zeroize();
        out
    };
    unsafe {
        LocalFree(out_blob.pbData as _);
    }
    Ok(plain)
}

#[cfg(not(windows))]
fn platform_protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    let mid = detect_os_machine_id().unwrap_or_default();
    let key = hmac_sha256_parts(mid.as_bytes(), &[b"unix-keystore-seal", entropy]);
    let mut out = vec![0u8; plaintext.len()];
    for (i, &b) in plaintext.iter().enumerate() {
        let pad = hmac_sha256_parts(&key, &[&(i as u64).to_le_bytes()])[0];
        out[i] = b ^ pad;
    }
    Ok(out)
}

#[cfg(not(windows))]
fn platform_unprotect(ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    platform_protect(ciphertext, entropy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cubehash_core::HardwareProvider;

    #[test]
    fn test_windows_dpapi_keystore_roundtrip_and_passphrase_protection() {
        let unique = format!(
            "cubehash_ks_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        let mut id1 = DeviceIdentity::load_or_create("alice_dpapi", Some(&dir), Some("pw-1")).unwrap();
        let pub1 = id1.ed25519_pub();
        let hw1 = id1.hardware_provider().device_hw_id();

        let peer_orig = DeviceIdentity::ephemeral_csprng("bob").unwrap();
        let peer_other = DeviceIdentity::ephemeral_csprng("bob").unwrap();
        id1.verify_or_pin_peer("bob", peer_orig.ed25519_pub()).unwrap();

        // Reloading with the same passphrase recovers exact Ed25519 identity, hardware ID, and TOFU pins
        let mut id2 = DeviceIdentity::load_or_create("alice_dpapi", Some(&dir), Some("pw-1")).unwrap();
        assert_eq!(id2.ed25519_pub(), pub1);
        assert_eq!(id2.hardware_provider().device_hw_id(), hw1);
        assert!(id2.verify_or_pin_peer("bob", peer_orig.ed25519_pub()).is_ok());
        assert!(id2.verify_or_pin_peer("bob", peer_other.ed25519_pub()).is_err());

        // Wrong passphrase cannot unseal DPAPI blob
        let err = DeviceIdentity::load_or_create("alice_dpapi", Some(&dir), Some("wrong-pw"))
            .err()
            .expect("wrong passphrase must fail");
        assert!(err.contains("DPAPI") || err.contains("failed"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_client_id_path_traversal_rejected() {
        assert!(DeviceIdentity::ephemeral_csprng("../escape").is_err());
        assert!(DeviceIdentity::ephemeral_csprng("").is_err());
    }
}
