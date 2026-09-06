//! ESP-derived identity and private-state logic; this module does not import ESP.
use crate::{Error, Result};
use iroh::{EndpointId, SecretKey};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

#[derive(Clone)]
pub struct Identity(pub(crate) SecretKey);
impl Default for Identity {
    fn default() -> Self {
        Self::generate()
    }
}
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Identity")
            .field(&self.endpoint_id())
            .finish()
    }
}
impl Identity {
    pub fn generate() -> Self {
        Self(SecretKey::generate())
    }
    pub fn from_secret_key(key: SecretKey) -> Self {
        Self(key)
    }
    /// Restore an identity from an application-managed private key store.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SecretKey::from_bytes(bytes))
    }
    /// Export the private key. The caller must keep these bytes confidential.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    pub fn endpoint_id(&self) -> EndpointId {
        self.0.public()
    }
    /// Store in an existing private directory. Explicitly replaces an existing private key file.
    #[cfg(unix)]
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(Error::Config(
                "key directory must be private (0700) and not a symlink",
            ));
        }
        match fs::symlink_metadata(path) {
            Ok(m) => validate(&m)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let temporary = parent.join(format!(".rtn-mq-key-{:032x}", rand::random::<u128>()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&self.0.to_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
    #[cfg(unix)]
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        validate(&fs::symlink_metadata(path)?)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        validate(&file.metadata()?)?;
        let mut bytes = Vec::with_capacity(33);
        file.take(33).read_to_end(&mut bytes)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Config("key must contain exactly 32 bytes"))?;
        Ok(Self(SecretKey::from_bytes(&bytes)))
    }
    #[cfg(not(unix))]
    pub fn save(&self, _: impl AsRef<Path>) -> Result<()> {
        Err(Error::Config(
            "use an application key store on this platform",
        ))
    }
    #[cfg(not(unix))]
    pub fn load(_: impl AsRef<Path>) -> Result<Self> {
        Err(Error::Config(
            "use an application key store on this platform",
        ))
    }
}
#[cfg(unix)]
fn validate(m: &fs::Metadata) -> Result<()> {
    if !m.is_file()
        || m.file_type().is_symlink()
        || m.nlink() != 1
        || m.permissions().mode() & 0o077 != 0
    {
        return Err(Error::Config(
            "key must be a private (0600), unlinked regular file",
        ));
    }
    Ok(())
}
