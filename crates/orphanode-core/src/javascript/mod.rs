//! Oxc-backed source parsing and compact fact extraction.

pub(crate) mod constants;
mod parse;

pub use parse::parse_file;
pub(crate) use parse::parse_file_with_limits;
