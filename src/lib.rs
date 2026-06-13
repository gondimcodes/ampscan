//! AmpScan Library
//!
//! Core components for AmpScan, including the scanning engine, database access,
//! PDF reporting, and authentication modules.

/// Authentication module
pub mod auth;
/// Database repository and models
pub mod db;
/// PDF Report generation
pub mod report;
/// Network scanning and probing
pub mod scanner;
