pub use anyhow::anyhow as new_error;
pub use anyhow::{bail, ensure};

pub type Error = anyhow::Error;
pub type Result<T> = std::result::Result<T, Error>;
