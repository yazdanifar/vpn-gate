//! Test doubles shared with other crates (behind the `testing` feature): a scripted in-memory SoftEther server and an
//! entropy source that replays recorded draws.

pub mod fake_softether;
pub mod replay_entropy;
