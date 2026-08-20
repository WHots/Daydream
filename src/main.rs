use std::process::ExitCode;
use std::path::Path;

mod core
{
    pub(crate) mod file_ops
    {
        pub(crate) mod file_processing;

        pub(crate) mod outputs
        {
            pub(crate) mod configs;
            pub(crate) mod file_triage_saves;
        }

        pub(crate) mod utils
        {
            pub(crate) mod apis;
            pub(crate) mod pdb;
            pub(crate) mod scanning;
            pub(crate) mod sections;
            pub(crate) mod strings;
            pub(crate) mod supports;
            pub(crate) mod validate;
        }
    }

    pub(crate) mod internal
    {
        pub(crate) mod imports
        {
            pub(crate) mod imports;
        }

        pub(crate) mod handles
        {
            pub(crate) mod handles;
        }
    }

    pub(crate) mod process_ops
    {
        pub(crate) mod outputs
        {
            pub(crate) mod config;
            pub(crate) mod process_triage_saves;
        }

        pub(crate) mod process_processing;

        pub(crate) mod procedures
        {
            pub(crate) mod debuginfo
            {
                #[allow(dead_code)]
                pub(crate) mod dbi;
                pub(crate) mod pdb;
            }

            pub(crate) mod foundation
            {
                pub(crate) mod validate_pe;
            }
            pub(crate) mod imports;
        }

        pub(crate) mod utils
        {
            pub(crate) mod mem;
            pub(crate) mod process;
            pub(crate) mod teb;
        }
    }

    pub(crate) mod global_utils
    {
        pub(crate) mod fileutils;
    }

    pub(crate) mod data
    {
        pub(crate) mod patterns64
        {
            pub(crate) mod patterns64;
        }

    }
}

use crate::core::file_ops::file_processing::process_file;
use crate::core::process_ops::process_processing::process_target;

/// Describes the explicit raw-file and process target modes accepted by the CLI.
const TARGET_USAGE: &str = "usage: daydream [-f <executable path> | -p <process id>]";


/// Program entry point. Defaults to analyzing this running process, or dispatches
/// an explicit raw-file or process target when arguments are supplied.
fn main() -> ExitCode
{
    let mut arguments = std::env::args().skip(1);
    let target_mode = match arguments.next()
    {
        Some(value) => value,
        None =>
        {
            let process_id = std::process::id();

            return match process_target(process_id)
            {
                Ok(_) => ExitCode::SUCCESS,
                Err(error) =>
                {
                    eprintln!("failed to process current process {}: {}", process_id, error);
                    ExitCode::FAILURE
                }
            };
        }
    };

    let target = match arguments.next()
    {
        Some(value) => value,
        None =>
        {
            eprintln!("{}", TARGET_USAGE);
            return ExitCode::FAILURE;
        }
    };

    if arguments.next().is_some()
    {
        eprintln!("{}", TARGET_USAGE);
        return ExitCode::FAILURE;
    }

    if target_mode == "-f"
    {
        return match process_file(Path::new(&target), false)
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) =>
            {
                eprintln!("failed to process file {:?}: {}", target, error);
                ExitCode::FAILURE
            }
        };
    }

    if target_mode != "-p"
    {
        eprintln!("{}", TARGET_USAGE);
        return ExitCode::FAILURE;
    }

    let pid = match target.parse::<u32>()
    {
        Ok(value) => value,
        Err(_) =>
        {
            eprintln!("invalid process id {:?}", target);
            return ExitCode::FAILURE;
        }
    };

    match process_target(pid)
    {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) =>
        {
            eprintln!("failed to process target process {}: {}", pid, error);
            ExitCode::FAILURE
        }
    }
}
