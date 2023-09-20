use ockam_core::compat::sync::Arc;
use ockam_core::Result;
use ockam_vault::{X25519PublicKey, X25519SecretKeyHandle};

use crate::models::TimestampInSeconds;
use crate::utils::now;
use crate::{
    Identifier, SecureChannelPurposeKey, SecureChannelPurposeKeyKey,
    SecureChannelPurposeKeyOptions, SecureChannelPurposeKeysCreation,
};

/// Default TTL for an Identity key
pub const DEFAULT_SECURE_CHANNEL_PURPOSE_KEY_TTL: TimestampInSeconds =
    TimestampInSeconds(5 * 365 * 24 * 60 * 60); // Five years

enum Key {
    Generate,
    Existing(X25519SecretKeyHandle),
    OnlyPublic(X25519PublicKey),
}

enum Ttl {
    CreatedNowWithTtl(TimestampInSeconds),
    FullTimestamps {
        created_at: TimestampInSeconds,
        expires_at: TimestampInSeconds,
    },
}

/// Builder for [`PurposeKey`]
pub struct SecureChannelPurposeKeyBuilder {
    purpose_keys_creation: Arc<SecureChannelPurposeKeysCreation>,

    identifier: Identifier,
    key: Key,
    ttl: Ttl,
}

impl SecureChannelPurposeKeyBuilder {
    /// Constructor
    pub fn new(
        purpose_keys_creation: Arc<SecureChannelPurposeKeysCreation>,
        identifier: Identifier,
    ) -> Self {
        let key = Key::Generate;

        Self {
            purpose_keys_creation,
            identifier,
            key,
            ttl: Ttl::CreatedNowWithTtl(DEFAULT_SECURE_CHANNEL_PURPOSE_KEY_TTL),
        }
    }

    /// Use an existing key for the Identity (should be present in the corresponding Vault)
    pub fn with_existing_key(mut self, secret_key_handle: X25519SecretKeyHandle) -> Self {
        self.key = Key::Existing(secret_key_handle);

        self
    }

    /// Will generate a fresh key with the given type
    pub fn with_random_key(mut self) -> Self {
        self.key = Key::Generate;
        self
    }

    /// Only public key is available, which is enough to attest it
    /// However, the calling side is then responsible for possession and proper use of the
    /// corresponding secret key
    pub fn with_public_key(mut self, public_key: X25519PublicKey) -> Self {
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
    pub async fn build_options(self) -> Result<SecureChannelPurposeKeyOptions> {
        let key = match self.key {
            Key::Generate => {
                let key = self
                    .purpose_keys_creation
                    .vault()
                    .secure_channel_vault
                    .generate_static_x25519_secret_key()
                    .await?;

                SecureChannelPurposeKeyKey::Secret(key)
            }
            Key::Existing(key) => SecureChannelPurposeKeyKey::Secret(key),
            Key::OnlyPublic(public_key) => SecureChannelPurposeKeyKey::Public(public_key),
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
            SecureChannelPurposeKeyOptions::new(self.identifier, key, created_at, expires_at);

        Ok(options)
    }

    /// Create the corresponding [`PurposeKey`]
    pub async fn build(self) -> Result<SecureChannelPurposeKey> {
        let purpose_keys_creation = self.purpose_keys_creation.clone();

        let options = self.build_options().await?;

        purpose_keys_creation
            .create_purpose_key_with_options(options)
            .await
    }
}
