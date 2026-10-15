//! Binary entry point for `keyfob`.
#![forbid(unsafe_code)]

/// `anyhow` is intentionally confined to the binary: the library exposes typed
/// errors, while the CLI converts them into a human-friendly report here.
fn main() -> anyhow::Result<()> {
    keyfob_idp::cli::run()?;
    Ok(())
}
