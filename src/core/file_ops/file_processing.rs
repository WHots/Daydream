use std::fmt;
use std::io;
use std::path::Path;

use crate::core::file_ops::outputs::file_triage_saves::{collect_file_triage, save_file_triage};
use crate::core::file_ops::utils::validate::{validate_target_file, FileValidationError};

/// Default minimum printable character count for file-string collection.
pub const DEFAULT_MINIMUM_FILE_STRING_LENGTH: usize = 4;

/// Explains whether file processing failed during PE validation or JSON persistence.
#[derive(Debug)]
pub enum FileProcessingError
{
    Validation(FileValidationError),
    Save(io::Error),
}


/// Validates, analyzes, and saves the available metadata from one raw PE file.
/// `path`: the executable path to read without loading or executing it.
///
/// Returns success after every file-side collector has completed, or the validation
/// or save error that prevented the complete triage workflow from finishing.
pub fn process_file(path: &Path) -> Result<(), FileProcessingError>
{
    let file = validate_target_file(path).map_err(FileProcessingError::Validation)?;
    let collection = collect_file_triage(&file, DEFAULT_MINIMUM_FILE_STRING_LENGTH);
    save_file_triage(path, &file, &collection, DEFAULT_MINIMUM_FILE_STRING_LENGTH).map_err(FileProcessingError::Save)?;

    Ok(())
}

impl fmt::Display for FileProcessingError
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Self::Validation(error) => write!(formatter, "{}", error),
            Self::Save(error) => write!(formatter, "failed to save file triage: {}", error),
        }
    }
}

impl std::error::Error for FileProcessingError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)>
    {
        match self
        {
            Self::Validation(error) => Some(error),
            Self::Save(error) => Some(error),
        }
    }
}
