use clap::Parser;
use std::{fs::OpenOptions, io::Write};
use unquarantine::{error::Error, UnQuarantine};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CliOpts {
    #[clap(short = 'i', long, value_name = "FILE")]
    input_file: String,
    #[clap(short = 'o', long, value_name = "FILE")]
    output_file: String,
}

fn main() -> Result<(), Error> {
    let cli = CliOpts::parse();

    let result = UnQuarantine::from_file(&cli.input_file);
    match result {
        Ok(res) => {
            for i in 0..res.unquarantined_buffer.len() {
                let mut output_file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&format!("{}_{}", &cli.output_file, i))?;
                output_file.write_all(&res.unquarantined_buffer[i])?;
            }
            println!("unquarantied for: {}", res.vendor);
        }
        Err(e) => println!("Error: {}", e),
    }

    Ok(())
}
