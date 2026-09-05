use rtn_mq::*;
#[test]
fn final_lease_release_controls_memory_budget() {
    let p = BufferPool::new(272, 16);
    let a = p.copy_from_slice(&[0; 16]).unwrap();
    let b = a.clone();
    assert!(matches!(p.copy_from_slice(&[0]), Err(Error::QueueFull)));
    drop(a);
    assert_eq!(p.resident_bytes(), 272);
    drop(b);
    assert_eq!(p.resident_bytes(), 0);
    let mut vector = Vec::with_capacity(32);
    vector.push(1);
    assert!(matches!(p.from_vec(vector), Err(Error::QueueFull)));
}
#[cfg(unix)]
#[test]
fn private_identity_roundtrip_and_rejection_of_links_modes_and_lengths() {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("key");
    let key = Identity::generate();
    key.save(&path).unwrap();
    assert_eq!(
        Identity::load(&path).unwrap().endpoint_id(),
        key.endpoint_id()
    );
    let link = dir.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(Identity::load(&link).is_err());
    assert!(key.save(&link).is_err());
    fs::remove_file(&link).unwrap();
    fs::hard_link(&path, &link).unwrap();
    assert!(Identity::load(&path).is_err());
    assert!(key.save(&path).is_err());
    fs::remove_file(&link).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Identity::load(&path).is_err());
    assert!(key.save(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, [0; 33]).unwrap();
    assert!(Identity::load(&path).is_err());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(key.save(&path).is_err());
}
