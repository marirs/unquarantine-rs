use clap::Parser;
use std::io::Write;
use unquarantine::{error::Error, unquarantine};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CliOpts {
    #[clap(short, long)]
    input_file: String,
    #[clap(short, long)]
    output_file: String,
}

fn main() -> Result<(), Error> {
    let cli = CliOpts::parse();

    let (n, b) = unquarantine(&cli.input_file)?;
    for i in 0..b.len() {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&format!("{}_{}", &cli.output_file, i))?;
        file.write_all(&b[i])?;
    }
    println!("unquarantied for: {}", n);
    std::process::exit(1)
}
