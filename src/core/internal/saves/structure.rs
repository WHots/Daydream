use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

/// The standard subdirectories used to organize a process dump.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DumpDirectory
{
    Memory,
    Yara,
    Strings,
    Pe,
    Reports,
    Metadata,
}


impl DumpDirectory
{
    /// Returns the on-disk folder name for this dump directory.
    ///
    /// Returns a static directory name that is safe to append under a dump root.
    pub fn as_name(self) -> &'static str
    {
        match self
        {
            DumpDirectory::Memory => "memory",
            DumpDirectory::Yara => "yara",
            DumpDirectory::Strings => "strings",
            DumpDirectory::Pe => "pe",
            DumpDirectory::Reports => "reports",
            DumpDirectory::Metadata => "metadata",
        }
    }
}


/// Describes the folder layout for a single organized process dump.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DumpLayout
{
    root: PathBuf,
    memory: PathBuf,
    yara: PathBuf,
    strings: PathBuf,
    pe: PathBuf,
    reports: PathBuf,
    metadata: PathBuf,
}


impl DumpLayout
{
    /// Builds the standard dump layout and ensures every directory exists.
    /// `root`: the root directory for a process dump.
    ///
    /// Returns `Ok(DumpLayout)` with all standard folders created, or an `io::Error` on failure.
    pub fn ensure(root: impl AsRef<Path>) -> io::Result<Self>
    {
        let layout = Self::from_root(root.as_ref().to_path_buf());

        layout.ensure_all_directories()?;

        Ok(layout)
    }

    /// Returns the root directory for the process dump.
    ///
    /// Returns the root path used to contain every organized dump category.
    pub fn root(&self) -> &Path
    {
        self.root.as_path()
    }

    /// Returns the directory path for a standard dump category.
    /// `directory`: the category whose directory should be returned.
    ///
    /// Returns the category directory path under the dump root.
    pub fn directory(&self, directory: DumpDirectory) -> &Path
    {
        match directory
        {
            DumpDirectory::Memory => self.memory.as_path(),
            DumpDirectory::Yara => self.yara.as_path(),
            DumpDirectory::Strings => self.strings.as_path(),
            DumpDirectory::Pe => self.pe.as_path(),
            DumpDirectory::Reports => self.reports.as_path(),
            DumpDirectory::Metadata => self.metadata.as_path(),
        }
    }

    /// Returns the memory dump directory path.
    ///
    /// Returns the folder intended for raw memory regions and memory-derived bytes.
    pub fn memory_directory(&self) -> &Path
    {
        self.memory.as_path()
    }

    /// Returns the YARA results directory path.
    ///
    /// Returns the folder intended for YARA rules, matches, and related scan output.
    pub fn yara_directory(&self) -> &Path
    {
        self.yara.as_path()
    }

    /// Returns the strings directory path.
    ///
    /// Returns the folder intended for extracted ASCII, UTF-8, and UTF-16LE strings.
    pub fn strings_directory(&self) -> &Path
    {
        self.strings.as_path()
    }

    /// Returns the PE analysis directory path.
    ///
    /// Returns the folder intended for PE headers, sections, imports, and image metadata.
    pub fn pe_directory(&self) -> &Path
    {
        self.pe.as_path()
    }

    /// Returns the report directory path.
    ///
    /// Returns the folder intended for summary reports and human-readable findings.
    pub fn reports_directory(&self) -> &Path
    {
        self.reports.as_path()
    }

    /// Returns the metadata directory path.
    ///
    /// Returns the folder intended for run metadata and process context.
    pub fn metadata_directory(&self) -> &Path
    {
        self.metadata.as_path()
    }

    /// Ensures a single standard dump category directory exists.
    /// `directory`: the category directory to create when missing.
    ///
    /// Returns the category directory path, or an `io::Error` when it cannot be created.
    pub fn ensure_directory(&self, directory: DumpDirectory) -> io::Result<&Path>
    {
        let path = self.directory(directory);

        fs::create_dir_all(path)?;

        Ok(path)
    }

    /// Writes bytes to a file inside a standard dump category.
    /// `directory`: the category directory that will receive the file.
    /// `file_name`: a relative file path under the category directory.
    /// `bytes`: the bytes to write to the output file.
    ///
    /// Returns the full output path, or an `io::Error` when the path or write fails.
    pub fn write_file(
        &self,
        directory: DumpDirectory,
        file_name: impl AsRef<Path>,
        bytes: &[u8],
    ) -> io::Result<PathBuf>
    {
        let directory = self.ensure_directory(directory)?;

        write_bytes(directory, file_name.as_ref(), bytes)
    }

    /// Writes bytes to a file inside the memory dump directory.
    /// `file_name`: a relative file path under the memory directory.
    /// `bytes`: the bytes to write to the output file.
    ///
    /// Returns the full output path, or an `io::Error` when the path or write fails.
    pub fn write_memory_file(
        &self,
        file_name: impl AsRef<Path>,
        bytes: &[u8],
    ) -> io::Result<PathBuf>
    {
        self.write_file(DumpDirectory::Memory, file_name, bytes)
    }

    /// Writes bytes to a file inside the YARA results directory.
    /// `file_name`: a relative file path under the YARA directory.
    /// `bytes`: the bytes to write to the output file.
    ///
    /// Returns the full output path, or an `io::Error` when the path or write fails.
    pub fn write_yara_file(
        &self,
        file_name: impl AsRef<Path>,
        bytes: &[u8],
    ) -> io::Result<PathBuf>
    {
        self.write_file(DumpDirectory::Yara, file_name, bytes)
    }

    /// Builds the standard dump layout paths without touching the filesystem.
    /// `root`: the root directory for a process dump.
    ///
    /// Returns a `DumpLayout` with every standard category path derived from `root`.
    fn from_root(root: PathBuf) -> Self
    {
        Self
        {
            memory: root.join(DumpDirectory::Memory.as_name()),
            yara: root.join(DumpDirectory::Yara.as_name()),
            strings: root.join(DumpDirectory::Strings.as_name()),
            pe: root.join(DumpDirectory::Pe.as_name()),
            reports: root.join(DumpDirectory::Reports.as_name()),
            metadata: root.join(DumpDirectory::Metadata.as_name()),
            root,
        }
    }

    /// Ensures the dump root and every standard category directory exists.
    ///
    /// Returns `Ok(())` when the full directory layout exists, or an `io::Error` on failure.
    fn ensure_all_directories(&self) -> io::Result<()>
    {
        fs::create_dir_all(&self.root)?;
        fs::create_dir_all(&self.memory)?;
        fs::create_dir_all(&self.yara)?;
        fs::create_dir_all(&self.strings)?;
        fs::create_dir_all(&self.pe)?;
        fs::create_dir_all(&self.reports)?;
        fs::create_dir_all(&self.metadata)?;

        Ok(())
    }
}


/// Ensures the standard process-dump directory structure exists.
/// `root`: the root directory for a process dump.
///
/// Returns `Ok(DumpLayout)` with every standard folder created, or an `io::Error` on failure.
pub fn ensure_dump_layout(root: impl AsRef<Path>) -> io::Result<DumpLayout>
{
    DumpLayout::ensure(root)
}


/// Writes bytes into a validated file path under a dump directory.
/// `directory`: the already-selected category directory.
/// `file_name`: a relative file path under the category directory.
/// `bytes`: the bytes to write to the output file.
///
/// Returns the full output path, or an `io::Error` when the path or write fails.
fn write_bytes(directory: &Path, file_name: &Path, bytes: &[u8]) -> io::Result<PathBuf>
{
    let output_path = resolve_output_path(directory, file_name)?;

    if let Some(parent) = output_path.parent()
    {
        fs::create_dir_all(parent)?;
    }

    fs::write(&output_path, bytes)?;

    Ok(output_path)
}


/// Resolves a relative file path beneath a dump directory.
/// `directory`: the category directory that owns the output file.
/// `file_name`: a relative path that must not escape `directory`.
///
/// Returns the full output path, or an `io::Error` for an unsafe file name.
fn resolve_output_path(directory: &Path, file_name: &Path) -> io::Result<PathBuf>
{
    validate_file_name(file_name)?;

    Ok(directory.join(file_name))
}


/// Validates that an output file path stays inside its selected dump directory.
/// `file_name`: the caller-supplied relative output path.
///
/// Returns `Ok(())` for a safe relative path, or an `io::Error` for absolute paths, parent traversal, or empty paths.
fn validate_file_name(file_name: &Path) -> io::Result<()>
{
    if file_name.as_os_str().is_empty()
    {
        return Err(invalid_file_name(file_name));
    }

    for component in file_name.components()
    {
        match component
        {
            Component::Normal(_) => {}
            _ => return Err(invalid_file_name(file_name)),
        }
    }

    Ok(())
}


/// Creates an invalid-input error for a rejected dump file name.
/// `file_name`: the unsafe or empty file name supplied by the caller.
///
/// Returns an `io::Error` describing the rejected file name.
fn invalid_file_name(file_name: &Path) -> io::Error
{
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "dump file name must be a relative child path: {}",
            file_name.display()
        ),
    )
}
