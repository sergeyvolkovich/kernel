use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match cfgtool::run(&args) {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("cfgtool: {e}");
            eprintln!("\n{}", cfgtool::USAGE);
            ExitCode::FAILURE
        }
    }
}
