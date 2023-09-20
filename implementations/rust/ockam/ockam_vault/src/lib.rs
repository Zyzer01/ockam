//! In order to support a variety of cryptographically capable hardware we maintain loose coupling between
//! our protocols and how a specific building block is invoked in a specific hardware.
//! This is achieved using an abstract Vault trait.
//!
//! A concrete implementation of the Vault trait is called an Ockam Vault.
//! Over time, and with help from the Ockam open source community, we plan to add vaults for
//! several TEEs, TPMs, HSMs, and Secure Enclaves.
//!
//! This crate provides a software-only Vault implementation that can be used when no cryptographic
//! hardware is available. The primary Ockam crate uses this as the default Vault implementation.
//!
//! The main [Ockam][main-ockam-crate-link] has optional dependency on this crate.
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(not(feature = "std"), not(feature = "alloc")))]
compile_error!(r#"The "no_std" feature currently requires the "alloc" feature"#);

#[cfg(feature = "std")]
extern crate core;

#[cfg(feature = "alloc")]
extern crate alloc;

/// Storage
#[cfg(feature = "storage")]
pub mod storage;

/// Errors
mod error;

/// Traits
mod traits;

/// Software implementation of Vault traits
mod software;

/// Main vault types: PublicKey, Secret, SecretAttributes etc...
mod types;

use cfg_if::cfg_if;
pub use error::*;
pub use software::*;
pub use traits::*;
pub use types::*;

// TODO: feature set compatibility check
cfg_if! {
    if #[cfg(any(not(feature = "disable_default_noise_protocol"), feature = "OCKAM_XX_25519_AES256_GCM_SHA256"))] {}
    else if #[cfg(feature = "OCKAM_XX_25519_ChaChaPolyBLAKE2s")] { }
    else if #[cfg(feature = "OCKAM_XX_25519_AES128_GCM_SHA256")] { }
    else {
        compile_error!{"NOISE protocol name not selected, please enable on of the following features: \"OCKAM_XX_25519_ChaChaPolyBLAKE2s\", \"OCKAM_XX_25519_AES128_GCM_SHA256\", \"OCKAM_XX_25519_AES256_GCM_SHA256\""}
    }
}
