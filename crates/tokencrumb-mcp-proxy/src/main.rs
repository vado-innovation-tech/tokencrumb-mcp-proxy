//! `tokencrumb` — the command-line entry point (see [`cli`]).

mod cli;

fn main() -> std::process::ExitCode {
    cli::main()
}
