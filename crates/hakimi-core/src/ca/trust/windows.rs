//! Windows：把 CA 写进 LocalMachine\ROOT。
//!
//! 由 `ca::trust` 原文件按平台切分而来，逻辑未改动。

use super::*;

pub(super) fn trust_status(
    sha1_hex: &str,
    _cert_path: &Path,
) -> Result<(bool, bool, Option<String>)> {
    let hash = hex::decode(sha1_hex).context("解析 SHA-1 指纹")?;
    let found = unsafe { win_store_find(&hash)? };
    Ok((true, found, None))
}

unsafe fn win_store_find(hash: &[u8]) -> Result<bool> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertOpenStore,
        CERT_FIND_HASH, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
        PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    #[repr(C)]
    struct CryptHashBlob {
        cb_data: u32,
        pb_data: *const u8,
    }

    let store_name: Vec<u16> = "ROOT\0".encode_utf16().collect();
    let store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        store_name.as_ptr() as *const c_void,
    );
    if store.is_null() {
        bail!("无法打开当前用户的根证书存储");
    }
    let blob = CryptHashBlob {
        cb_data: hash.len() as u32,
        pb_data: hash.as_ptr(),
    };
    let context = CertFindCertificateInStore(
        store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        &blob as *const _ as *const c_void,
        std::ptr::null(),
    );
    if !context.is_null() {
        CertFreeCertificateContext(context);
    }
    CertCloseStore(store, 0);
    Ok(!context.is_null())
}

pub(super) fn install_cert(der: &[u8], _pem_path: &Path) -> Result<()> {
    unsafe { win_store_add(der) }
}

unsafe fn win_store_add(der: &[u8]) -> Result<()> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::Cryptography::{
        CertAddEncodedCertificateToStore, CertCloseStore, CertOpenStore,
        CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
        X509_ASN_ENCODING,
    };
    let store_name: Vec<u16> = "ROOT\0".encode_utf16().collect();
    let store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        store_name.as_ptr() as *const c_void,
    );
    if store.is_null() {
        bail!("无法打开当前用户的根证书存储");
    }
    let added = CertAddEncodedCertificateToStore(
        store,
        X509_ASN_ENCODING,
        der.as_ptr(),
        der.len() as u32,
        CERT_STORE_ADD_REPLACE_EXISTING,
        std::ptr::null_mut(),
    );
    CertCloseStore(store, 0);
    if added == 0 {
        bail!("Windows 拒绝把 CA 证书写入根证书存储");
    }
    Ok(())
}

pub(super) fn uninstall_by_sha1(sha1_hex: &str, _remove_trust: bool) -> Result<()> {
    let hash = hex::decode(sha1_hex).context("解析 SHA-1 指纹")?;
    unsafe { win_store_delete(&hash) }
}

unsafe fn win_store_delete(hash: &[u8]) -> Result<()> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertDeleteCertificateFromStore, CertFindCertificateInStore, CertOpenStore,
        CERT_FIND_HASH, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
        PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    #[repr(C)]
    struct CryptHashBlob {
        cb_data: u32,
        pb_data: *const u8,
    }

    let store_name: Vec<u16> = "ROOT\0".encode_utf16().collect();
    let store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        store_name.as_ptr() as *const c_void,
    );
    if store.is_null() {
        bail!("无法打开当前用户的根证书存储");
    }
    let blob = CryptHashBlob {
        cb_data: hash.len() as u32,
        pb_data: hash.as_ptr(),
    };
    let context = CertFindCertificateInStore(
        store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        &blob as *const _ as *const c_void,
        std::ptr::null(),
    );
    if context.is_null() {
        // Already gone: uninstall is a no-op, not a failure.
        CertCloseStore(store, 0);
        return Ok(());
    }
    let deleted = CertDeleteCertificateFromStore(context);
    CertCloseStore(store, 0);
    if deleted == 0 {
        bail!("Windows 拒绝删除 CA 证书");
    }
    Ok(())
}
