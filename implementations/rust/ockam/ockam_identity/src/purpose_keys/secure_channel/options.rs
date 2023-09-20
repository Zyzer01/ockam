use crate::{Identifier, TimestampInSeconds};
use ockam_vault::{X25519PublicKey, X25519SecretKeyHandle};

#[derive(Clone)]
/// PurposeKey key.
pub enum SecureChannelPurposeKeyKey {
    /// We have access to the PurposeKey secret to key to then use it
    Secret(X25519SecretKeyHandle),
    /// Only Public Key accessible, we can still attest such PurposeKey, but won't be able to use it.
    /// The calling side may use corresponding secret key though.
    Public(X25519PublicKey),
}

/// Options to create a Purpose Key
#[derive(Clone)]
pub struct SecureChannelPurposeKeyOptions {
    pub(super) identifier: Identifier,
    pub(super) key: SecureChannelPurposeKeyKey,
    pub(super) created_at: TimestampInSeconds,
    pub(super) expires_at: TimestampInSeconds,
}

impl SecureChannelPurposeKeyOptions {
    /// Constructor
    pub fn new(
        identifier: Identifier,
        key: SecureChannelPurposeKeyKey,
        created_at: TimestampInSeconds,
        expires_at: TimestampInSeconds,
    ) -> Self {
        Self {
            identifier,
            key,
            created_at,
            expires_at,
        }
    }

    /// [`Identifier`] of the issuer
    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    /// Key
    pub fn key(&self) -> &SecureChannelPurposeKeyKey {
        &self.key
    }

    /// Creation timestamp
    pub fn created_at(&self) -> TimestampInSeconds {
        self.created_at
    }

    /// Expiration timestamp
    pub fn expires_at(&self) -> TimestampInSeconds {
        self.expires_at
    }
}
