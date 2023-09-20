use crate::models::utils::get_versioned_data;
use crate::models::{
    CredentialSigningKey, PurposeKeyAttestation, PurposeKeyAttestationData,
    PurposeKeyAttestationSignature, VersionedData,
};

use ockam_core::Result;
use ockam_vault::{Signature, VerifyingPublicKey};

impl PurposeKeyAttestation {
    /// Extract [`VersionedData`]
    pub fn get_versioned_data(&self) -> Result<VersionedData> {
        get_versioned_data(&self.data)
    }
}

impl PurposeKeyAttestationData {
    /// Extract [`PurposeKeyAttestationData`] from [`VersionedData`]
    pub fn get_data(versioned_data: &VersionedData) -> Result<Self> {
        Ok(minicbor::decode(&versioned_data.data)?)
    }
}

impl From<PurposeKeyAttestationSignature> for Signature {
    fn from(value: PurposeKeyAttestationSignature) -> Self {
        match value {
            PurposeKeyAttestationSignature::Ed25519Signature(value) => Self::EdDSACurve25519(value),
            PurposeKeyAttestationSignature::P256ECDSASignature(value) => {
                Self::ECDSASHA256CurveP256(value)
            }
        }
    }
}

impl From<Signature> for PurposeKeyAttestationSignature {
    fn from(value: Signature) -> Self {
        match value {
            Signature::EdDSACurve25519(value) => Self::Ed25519Signature(value),
            Signature::ECDSASHA256CurveP256(value) => Self::P256ECDSASignature(value),
        }
    }
}

impl From<CredentialSigningKey> for VerifyingPublicKey {
    fn from(value: CredentialSigningKey) -> Self {
        match value {
            CredentialSigningKey::Ed25519PublicKey(value) => Self::EdDSACurve25519(value),
            CredentialSigningKey::P256ECDSAPublicKey(value) => Self::ECDSASHA256CurveP256(value),
        }
    }
}

impl From<VerifyingPublicKey> for CredentialSigningKey {
    fn from(value: VerifyingPublicKey) -> Self {
        match value {
            VerifyingPublicKey::EdDSACurve25519(value) => Self::Ed25519PublicKey(value),
            VerifyingPublicKey::ECDSASHA256CurveP256(value) => Self::P256ECDSAPublicKey(value),
        }
    }
}
