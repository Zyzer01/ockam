use ockam_core::compat::sync::Arc;
use ockam_core::Result;
use ockam_vault::{SigningKeyType, SigningSecretKeyHandle, VerifyingPublicKey};

use crate::models::TimestampInSeconds;
use crate::utils::now;
use crate::{
    CredentialPurposeKey, CredentialPurposeKeyKey, CredentialPurposeKeyOptions,
    CredentialPurposeKeysCreation, Identifier,
};

/// Default TTL for an Identity key
pub const DEFAULT_CREDENTIAL_PURPOSE_KEY_TTL: TimestampInSeconds =
    TimestampInSeconds(5 * 365 * 24 * 60 * 60); // Five years

enum Key {
    Generate(SigningKeyType),
    Existing(SigningSecretKeyHandle),
    OnlyPublic(VerifyingPublicKey),
}

enum Ttl {
    CreatedNowWithTtl(TimestampInSeconds),
    FullTimestamps {
        created_at: TimestampInSeconds,
        expires_at: TimestampInSeconds,
    },
}

/// Builder for [`PurposeKey`]
pub struct CredentialPurposeKeyBuilder {
    purpose_keys_creation: Arc<CredentialPurposeKeysCreation>,

    identifier: Identifier,
    key: Key,
    ttl: Ttl,
}

impl CredentialPurposeKeyBuilder {
    /// Constructor
    pub fn new(
        purpose_keys_creation: Arc<CredentialPurposeKeysCreation>,
        identifier: Identifier,
    ) -> Self {
        let key = Key::Generate(SigningKeyType::EdDSACurve25519);

        Self {
            purpose_keys_creation,
            identifier,
            key,
            ttl: Ttl::CreatedNowWithTtl(DEFAULT_CREDENTIAL_PURPOSE_KEY_TTL),
        }
    }

    /// Use an existing key for the Identity (should be present in the corresponding Vault)
    pub fn with_existing_key(mut self, secret_key_handle: SigningSecretKeyHandle) -> Self {
        self.key = Key::Existing(secret_key_handle);

        self
    }

    /// Will generate a fresh key with the given type
    pub fn with_random_key(mut self, key_type: SigningKeyType) -> Self {
        self.key = Key::Generate(key_type);
        self
    }

    /// Only public key is available, which is enough to attest it
    /// However, the calling side is then responsible for possession and proper use of the
    /// corresponding secret key
    pub fn with_public_key(mut self, public_key: VerifyingPublicKey) -> Self {
        self.key = Key::OnlyPublic(public_key);
        self
    }

    /// Set created_at and expires_at timestamps
    pub fn with_timestamps(
        mut self,
        created_at: TimestampInSeconds,
        expires_at: TimestampInSeconds,
    ) -> Self {
        self.ttl = Ttl::FullTimestamps {
            created_at,
            expires_at,
        };
        self
    }

    /// Will set created_at to now and compute expires_at given the TTL
    pub fn with_ttl(mut self, ttl_seconds: impl Into<TimestampInSeconds>) -> Self {
        self.ttl = Ttl::CreatedNowWithTtl(ttl_seconds.into());
        self
    }

    /// Create the corresponding [`PurposeKeyOptions`] object
    pub async fn build_options(self) -> Result<CredentialPurposeKeyOptions> {
        let key = match self.key {
            Key::Generate(stype) => {
                let key = self
                    .purpose_keys_creation
                    .vault()
                    .credential_vault
                    .generate_signing_secret_key(stype)
                    .await?;

                CredentialPurposeKeyKey::Secret(key)
            }
            Key::Existing(key) => CredentialPurposeKeyKey::Secret(key),
            Key::OnlyPublic(public_key) => CredentialPurposeKeyKey::Public(public_key),
        };

        let (created_at, expires_at) = match self.ttl {
            Ttl::CreatedNowWithTtl(ttl) => {
                let created_at = now()?;
                let expires_at = created_at + ttl;

                (created_at, expires_at)
            }
            Ttl::FullTimestamps {
                created_at,
                expires_at,
            } => (created_at, expires_at),
        };

        let options =
            CredentialPurposeKeyOptions::new(self.identifier, key, created_at, expires_at);

        Ok(options)
    }

    /// Create the corresponding [`PurposeKey`]
    pub async fn build(self) -> Result<CredentialPurposeKey> {
        let purpose_keys_creation = self.purpose_keys_creation.clone();

        let options = self.build_options().await?;

        purpose_keys_creation
            .create_purpose_key_with_options(options)
            .await
    }
}
