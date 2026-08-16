use core::ptr;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufWriter, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use windows_sys::Win32::Security::Cryptography::{BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash, BCryptHashData, BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALGORITHM};

/// Calculates the Shannon entropy of a file given its path.
/// The Shannon entropy is a measure of the randomness or unpredictability of the file's content.
/// A higher entropy value indicates a more random file, while a lower value indicates a more predictable file.
///
/// `file_path`: the path to the file for which to calculate the entropy.
///
/// Returns `Ok(f64)` with the calculated entropy if successful, or an `io::Error` if an error occurs.
pub fn get_file_entropy(file_path: &OsStr) -> io::Result<f64>
{
    let path = Path::new(file_path);
    let mut file = File::open(path)?;

    let mut frequency: HashMap<u8, i64> = HashMap::new();
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer)?;

    if buffer.is_empty()
    {
        return Ok(0.0);
    }

    for &byte in &buffer
    {
        *frequency.entry(byte).or_insert(0) += 1;
    }

    let total_bytes = buffer.len() as f64;
    let entropy = frequency.values().fold(0.0, |acc, &freq| {
        if freq > 0
        {
            let probability = freq as f64 / total_bytes;
            acc - (probability * probability.log2())
        }
        else
        {
            acc
        }
    });

    Ok(entropy)
}


/// Computes the SHA-256 digest of a process's executable image on disk.
/// The file is streamed through the Windows CNG (BCrypt) SHA-256 provider in fixed-size
/// chunks so the whole image never has to be held in memory at once.
///
/// `exec_path`: the on-disk path to the process's executable to hash.
///
/// Returns `Ok(String)` with the lowercase hexadecimal digest on success, or an `io::Error`
/// if the file cannot be read or the CNG hashing operation fails.
pub fn get_file_sha256(exec_path: &OsStr) -> io::Result<String>
{
    let mut file = File::open(Path::new(exec_path))?;

    let mut algorithm: BCRYPT_ALG_HANDLE = ptr::null_mut();
    // SAFETY: Every pointer is valid for the call, and the returned provider is closed below.
    let status = unsafe { BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_SHA256_ALGORITHM, ptr::null(), 0) };
    if status < 0
    {
        return Err(io::Error::other(format!("BCryptOpenAlgorithmProvider failed: {status:#x}")));
    }

    let result = hash_reader(&mut file, algorithm);

    // SAFETY: `algorithm` was successfully opened above and is closed exactly once here.
    unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };

    result
}


/// Computes the SHA-256 digest of an already retained byte buffer.
/// `data`: the exact bytes whose identity should be preserved without reopening a path.
///
/// Returns the lowercase hexadecimal digest, or an `io::Error` when CNG hashing fails.
pub fn get_data_sha256(data: &[u8]) -> io::Result<String>
{
    let mut reader = Cursor::new(data);
    let mut algorithm: BCRYPT_ALG_HANDLE = ptr::null_mut();
    // SAFETY: Every pointer is valid for the call, and the returned provider is closed below.
    let status = unsafe { BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_SHA256_ALGORITHM, ptr::null(), 0) };
    if status < 0
    {
        return Err(io::Error::other(format!("BCryptOpenAlgorithmProvider failed: {status:#x}")));
    }

    let result = hash_reader(&mut reader, algorithm);

    // SAFETY: `algorithm` was successfully opened above and is closed exactly once here.
    unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };

    result
}


/// Extracts a non-empty, extension-free name that is safe for a direct-child output path.
/// `file_path`: the source path whose final file stem should identify an output root.
///
/// Returns the lossy Unicode file stem, or an invalid-input error.
pub fn get_validated_file_stem(file_path: &Path) -> io::Result<String>
{
    let file_stem = match file_path.file_stem()
    {
        Some(value) if !value.is_empty() => value.to_string_lossy().into_owned(),
        _ =>
        {
            eprintln!("failed to derive a safe file stem for an output directory");
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "file path has no usable file stem"));
        }
    };

    if file_stem == "." || file_stem == ".."
    {
        eprintln!("refusing unsafe output file stem {:?}", file_stem);
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "file stem is unsafe"));
    }

    Ok(file_stem)
}


/// Validates a SHA-256 digest before it is used as an output-path component.
/// `sha256`: the digest required to contain exactly 64 hexadecimal characters.
///
/// Returns success for a valid digest, or an invalid-input error.
pub fn validate_sha256_digest(sha256: &str) -> io::Result<()>
{
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        eprintln!("refusing invalid SHA-256 value for an output directory");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "SHA-256 must contain exactly 64 hexadecimal characters"));
    }

    Ok(())
}


/// Serializes and overwrites one pretty-formatted JSON file inside an output directory.
/// `directory`: the already-selected scan root or category directory.
/// `file_name`: one local file-name component with no traversal or subdirectories.
/// `value`: the structured JSON value to serialize.
///
/// Returns the path written on success, or an I/O error for invalid names,
/// serialization failures, directory creation failures, or file writes.
pub fn write_json_file(directory: &Path, file_name: &str, value: &Value) -> io::Result<PathBuf>
{
    validate_file_name(file_name)?;

    let output_path = directory.join(file_name);
    fs::create_dir_all(directory)?;

    let output_file = File::create(&output_path)?;
    let mut writer = BufWriter::new(output_file);

    serde_json::to_writer_pretty(&mut writer, value).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    writer.flush()?;

    Ok(output_path)
}


/// Rejects empty, absolute, nested, and traversal-based JSON output names.
/// `file_name`: the local output name required to contain one normal path component.
///
/// Returns success for a safe name, or an invalid-input error.
fn validate_file_name(file_name: &str) -> io::Result<()>
{
    let path = Path::new(file_name);
    let mut components = path.components();
    let valid = matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();

    if !valid
    {
        eprintln!("refusing unsafe triage output file name {:?}", file_name);
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "output file name must be one normal path component"));
    }

    Ok(())
}


/// Streams a reader through a CNG hash object and returns its hexadecimal digest.
/// `reader`: the byte source to read to completion and feed into the hash.
/// `algorithm`: an open BCrypt SHA-256 algorithm provider handle.
///
/// Returns `Ok(String)` with the lowercase hexadecimal digest on success, or an `io::Error`
/// if reading or any CNG hashing step fails. The hash object is always destroyed before return.
#[inline(always)]
fn hash_reader(reader: &mut impl Read, algorithm: BCRYPT_ALG_HANDLE) -> io::Result<String>
{
    let mut hash: BCRYPT_HASH_HANDLE = ptr::null_mut();
    // SAFETY: `algorithm` is a live SHA-256 provider and the output handle pointer is valid.
    let status = unsafe { BCryptCreateHash(algorithm, &mut hash, ptr::null_mut(), 0, ptr::null(), 0, 0) };
    if status < 0
    {
        return Err(io::Error::other(format!("BCryptCreateHash failed: {status:#x}")));
    }

    let mut buffer = [0u8; 64 * 1024];
    loop
    {
        let read = match reader.read(&mut buffer)
        {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) =>
            {
                // SAFETY: `hash` was successfully created above and is destroyed exactly once on this path.
                unsafe { BCryptDestroyHash(hash) };
                return Err(error);
            }
        };

        // SAFETY: `hash` is live and `buffer[..read]` remains valid for the duration of the call.
        let status = unsafe { BCryptHashData(hash, buffer.as_ptr(), read as u32, 0) };
        if status < 0
        {
            // SAFETY: `hash` was successfully created above and is destroyed exactly once on this path.
            unsafe { BCryptDestroyHash(hash) };
            return Err(io::Error::other(format!("BCryptHashData failed: {status:#x}")));
        }
    }

    let mut digest = [0u8; 32];
    // SAFETY: `hash` is live and the complete digest output buffer is writable.
    let status = unsafe { BCryptFinishHash(hash, digest.as_mut_ptr(), digest.len() as u32, 0) };

    // SAFETY: `hash` was successfully created above and is destroyed exactly once here.
    unsafe { BCryptDestroyHash(hash) };

    if status < 0
    {
        return Err(io::Error::other(format!("BCryptFinishHash failed: {status:#x}")));
    }

    Ok(to_hex(&digest))
}


/// Encodes a byte slice as a lowercase hexadecimal string.
/// `bytes`: the raw bytes to encode, two hex characters per byte.
///
/// Returns the encoded `String`.
#[inline(always)]
fn to_hex(bytes: &[u8]) -> String
{
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes
    {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }

    out
}
