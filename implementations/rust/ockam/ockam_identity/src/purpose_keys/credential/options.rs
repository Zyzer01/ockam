use crate::{Identifier, TimestampInSeconds};
use ockam_vault::{SigningSecretKeyHandle, VerifyingPublicKey};

#[derive(Clone)]
/// PurposeKey key.
pub enum CredentialPurposeKeyKey {
    /// We have access to the PurposeKey secret to key to then use it
    Secret(SigningSecretKeyHandle),
    /// Only Public Key accessible, we can still attest such PurposeKey, but won't be able to use it.
    /// The calling side may use corresponding secret key though.
    Public(VerifyingPublicKey),
}

/// Options to create a Purpose Key
#[derive(Clone)]
pub struct CredentialPurposeKeyOptions {
    pub(super) identifier: Identifier,
    pub(super) key: CredentialPurposeKeyKey,
    pub(super) created_at: TimestampInSeconds,
    pub(super) expires_at: TimestampInSeconds,
}

impl CredentialPurposeKeyOptions {
    /// Constructor
    pub fn new(
        identifier: Identifier,
        key: CredentialPurposeKeyKey,
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
    pub fn key(&self) -> &CredentialPurposeKeyKey {
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
