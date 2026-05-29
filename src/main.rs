//! `unquarantine` — command-line front-end for the library.
//!
//! Restores/decrypts files quarantined by ~40 AV products. For every restored
//! item it prints the detected vendor and writes the output with a **trailing
//! underscore** in the filename, so a restored (potentially malicious) sample
//! cannot be executed by a careless double-click.

use clap::Parser;
use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};
use unquarantine::UnQuarantine;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Restore/decrypt files quarantined by ~40 AV products",
    long_about = None
)]
struct Cli {
    /// One or more quarantined files to restore.
    #[arg(required = true, value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Directory to write restored files into (default: alongside each input).
    #[arg(short, long, value_name = "DIR")]
    outdir: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Some(dir) = &cli.outdir {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("[!] cannot create output directory {}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
    }

    let mut all_ok = true;
    for input in &cli.files {
        all_ok &= process_one(&cli, input);
    }

    if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Returns `true` on full success for this input.
fn process_one(cli: &Cli, input: &Path) -> bool {
    let shown = input.display();
    let Some(input_str) = input.to_str() else {
        eprintln!("[!] {shown}: non-UTF8 path, skipping");
        return false;
    };

    let res = match UnQuarantine::from_file(input_str) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("[!] {shown}: {e}");
            return false;
        }
    };

    let buffers = res.get_unquarantined_buffer();
    println!(
        "[+] {shown}: detected {} ({} item(s))",
        res.get_vendor(),
        buffers.len()
    );

    let stem = input
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "restored".to_string());
    let dir = cli
        .outdir
        .clone()
        .or_else(|| input.parent().map(PathBuf::from))
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."));

    let mut ok = true;
    for (i, buf) in buffers.iter().enumerate() {
        // Trailing `_` is deliberate: keeps the restored sample non-executable.
        let out = dir.join(format!("{stem}.{i:02}_"));
        match fs::write(&out, buf) {
            Ok(()) => println!("    -> {} ({} bytes)", out.display(), buf.len()),
            Err(e) => {
                eprintln!("    [!] failed to write {}: {e}", out.display());
                ok = false;
            }
        }
    }
    ok
}
