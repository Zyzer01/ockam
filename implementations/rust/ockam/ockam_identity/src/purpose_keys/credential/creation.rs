use ockam_core::compat::sync::Arc;
use ockam_core::{Error, Result};

use crate::models::{
    Identifier, PurposeKeyAttestation, PurposeKeyAttestationData, PurposePublicKey, VersionedData,
};
use crate::purpose_keys::storage::PurposeKeysRepository;
use crate::{
    CredentialPurposeKey, CredentialPurposeKeyBuilder, CredentialPurposeKeyKey,
    CredentialPurposeKeyOptions, IdentitiesKeys, IdentitiesReader, Identity, IdentityError,
    Purpose, PurposeKeysVerification, Vault,
};

/// This struct supports all the services related to identities
#[derive(Clone)]
pub struct CredentialPurposeKeysCreation {
    vault: Vault,
    identities_reader: Arc<dyn IdentitiesReader>,
    identity_keys: Arc<IdentitiesKeys>,
    repository: Arc<dyn PurposeKeysRepository>,
}

impl CredentialPurposeKeysCreation {
    /// Create a new identities module
    pub(crate) fn new(
        vault: Vault,
        identities_reader: Arc<dyn IdentitiesReader>,
        identity_keys: Arc<IdentitiesKeys>,
        repository: Arc<dyn PurposeKeysRepository>,
    ) -> Self {
        Self {
            vault,
            identities_reader,
            identity_keys,
            repository,
        }
    }

    /// Return [`PurposeKeysRepository`] instance
    pub fn repository(&self) -> Arc<dyn PurposeKeysRepository> {
        self.repository.clone()
    }

    /// Create [`PurposeKeysVerification`]
    pub fn purpose_keys_verification(&self) -> Arc<PurposeKeysVerification> {
        Arc::new(PurposeKeysVerification::new(
            self.vault.verifying_vault.clone(),
            self.identities_reader.clone(),
        ))
    }

    /// Get an instance of [`PurposeKeyBuilder`]
    pub fn purpose_key_builder(&self, identifier: &Identifier) -> CredentialPurposeKeyBuilder {
        CredentialPurposeKeyBuilder::new(
            Arc::new(Self::new(
                self.vault.clone(),
                self.identities_reader.clone(),
                self.identity_keys.clone(),
                self.repository.clone(),
            )),
            identifier.clone(),
        )
    }

    /// Return the [`Vault`]
    pub fn vault(&self) -> &Vault {
        &self.vault
    }
}

impl CredentialPurposeKeysCreation {
    /// Create a [`PurposeKey`]
    pub async fn create_purpose_key(
        &self,
        identifier: &Identifier,
    ) -> Result<CredentialPurposeKey> {
        let builder = self.purpose_key_builder(identifier);
        builder.build().await
    }

    /// Create a [`PurposeKey`]
    pub async fn create_purpose_key_with_options(
        &self,
        options: CredentialPurposeKeyOptions,
    ) -> Result<CredentialPurposeKey> {
        // TODO: Check if such key already exists and rewrite it correctly (also delete from the Vault)

        let mut attestation_options = options.clone();

        let (secret_key, public_key) = match options.key {
            CredentialPurposeKeyKey::Secret(key) => {
                let public_key = self
                    .vault
                    .credential_vault
                    .get_verifying_public_key(&key)
                    .await?;
                (key, public_key)
            }
            CredentialPurposeKeyKey::Public(_) => {
                return Err(IdentityError::ExpectedSecretKeyInsteadOfPublic.into());
            }
        };

        attestation_options.key = CredentialPurposeKeyKey::Public(public_key.clone());

        let (attestation, attestation_data) = self.attest_purpose_key(attestation_options).await?;

        let identifier = options.identifier.clone();

        self.repository
            .set_purpose_key(&identifier, Purpose::Credentials, &attestation)
            .await?;

        let purpose_key = CredentialPurposeKey::new(
            identifier,
            secret_key,
            public_key,
            attestation_data,
            attestation,
        );

        Ok(purpose_key)
    }

    /// Attest a PurposeKey given its public key
    pub async fn attest_purpose_key(
        &self,
        options: CredentialPurposeKeyOptions,
    ) -> Result<(PurposeKeyAttestation, PurposeKeyAttestationData)> {
        let public_key = match options.key {
            CredentialPurposeKeyKey::Secret { .. } => {
                return Err(IdentityError::ExpectedPublicKeyInsteadOfSecret.into())
            }
            CredentialPurposeKeyKey::Public(public_key) => public_key,
        };

        let public_key = PurposePublicKey::CredentialSigning(public_key.into());

        let identifier = options.identifier.clone();
        let identity_change_history = self.identities_reader.get_identity(&identifier).await?;
        let identity = Identity::import_from_change_history(
            Some(&identifier),
            identity_change_history,
            self.vault.verifying_vault.clone(),
        )
        .await?;

        let purpose_key_attestation_data = PurposeKeyAttestationData {
            subject: identifier,
            subject_latest_change_hash: identity.latest_change_hash()?.clone(),
            public_key,
            created_at: options.created_at,
            expires_at: options.expires_at,
        };

        let purpose_key_attestation_data_binary = minicbor::to_vec(&purpose_key_attestation_data)?;

        let versioned_data = VersionedData {
            version: 1,
            data: purpose_key_attestation_data_binary,
        };
        let versioned_data = minicbor::to_vec(&versioned_data)?;

        let versioned_data_hash = self.vault.verifying_vault.sha256(&versioned_data).await?;

        let signing_key = self.identity_keys.get_secret_key(&identity).await?;
        let signature = self
            .vault
            .identity_vault
            .sign(&signing_key, &versioned_data_hash.0)
            .await?;
        let signature = signature.into();

        let attestation = PurposeKeyAttestation {
            data: versioned_data,
            signature,
        };

        Ok((attestation, purpose_key_attestation_data))
    }

    /// Will try to get own Purpose Key from the repository, if that doesn't succeed - new one
    /// will be generated
    pub async fn get_or_create_purpose_key(
        &self,
        identifier: &Identifier,
    ) -> Result<CredentialPurposeKey> {
        let existent_key = async {
            let purpose_key_attestation = self
                .repository
                .get_purpose_key(identifier, Purpose::Credentials)
                .await?;

            let purpose_key = self.import_purpose_key(&purpose_key_attestation).await?;

            Ok::<CredentialPurposeKey, Error>(purpose_key)
        }
        .await;

        match existent_key {
            Ok(purpose_key) => Ok(purpose_key),
            // TODO: Should it be customizable?
            Err(_) => self.create_purpose_key(identifier).await,
        }
    }

    /// Get own Purpose Key from the repository
    pub async fn get_purpose_key(&self, identifier: &Identifier) -> Result<CredentialPurposeKey> {
        let purpose_key_attestation = self
            .repository
            .get_purpose_key(identifier, Purpose::Credentials)
            .await?;

        self.import_purpose_key(&purpose_key_attestation).await
    }

    /// Import own [`PurposeKey`] from its [`PurposeKeyAttestation`]
    /// It's assumed that the corresponding secret exists in the Vault
    pub async fn import_purpose_key(
        &self,
        attestation: &PurposeKeyAttestation,
    ) -> Result<CredentialPurposeKey> {
        let purpose_key_data = self
            .purpose_keys_verification()
            .verify_purpose_key_attestation(None, attestation)
            .await?;

        let (key_id, public_key) = match purpose_key_data.public_key.clone() {
            PurposePublicKey::SecureChannelStatic(_public_key) => {
                panic!() // FIXME
            }
            PurposePublicKey::CredentialSigning(public_key) => {
                let public_key = public_key.into();
                let key = self
                    .vault
                    .credential_vault
                    .get_secret_key_handle(&public_key)
                    .await?;
                (key, public_key)
            }
        };

        let purpose_key = CredentialPurposeKey::new(
            purpose_key_data.subject.clone(),
            key_id,
            public_key,
            purpose_key_data,
            attestation.clone(),
        );

        Ok(purpose_key)
    }
}
