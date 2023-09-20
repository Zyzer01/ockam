use ockam_core::compat::vec::Vec;

use crate::models::{ChangeHash, Identifier, TimestampInSeconds};

use minicbor::{Decode, Encode};
use ockam_vault::{
    ECDSASHA256CurveP256PublicKey, ECDSASHA256CurveP256Signature, EdDSACurve25519PublicKey,
    EdDSACurve25519Signature, X25519PublicKey,
};

/// Self-signed Attestation of an [`super::super::identity::Identity`] associating
/// a [`super::super::purpose_key::PurposeKey`] with itself
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[rustfmt::skip]
pub struct PurposeKeyAttestation {
    /// CBOR serialized [`super::VersionedData`]
    /// where VersionedData::data is CBOR serialized [`PurposeKeyAttestationData`]
    #[cbor(with = "minicbor::bytes")]
    #[n(0)] pub data: Vec<u8>,
    /// Signature over data field using a key from [`super::super::identity::Identity`]
    #[n(1)] pub signature: PurposeKeyAttestationSignature,
}

/// Signature over data field using a key from [`super::super::identity::Identity`]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[rustfmt::skip]
pub enum PurposeKeyAttestationSignature {
    /// Signature using EdDSA Ed25519 key from the corresponding [`super::super::identity::Identity`]
    #[n(0)] Ed25519Signature(#[n(0)] EdDSACurve25519Signature),
    /// Signature using ECDSA P256 key from the corresponding [`super::super::identity::Identity`]
    #[n(1)] P256ECDSASignature(#[n(0)] ECDSASHA256CurveP256Signature),
}

/// Data inside a [`PurposeKeyAttestation`]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[rustfmt::skip]
pub struct PurposeKeyAttestationData {
    /// [`Identifier`] of the [`super::super::identity::Identity`] this Purpose Key belongs to
    #[n(0)] pub subject: Identifier,
    /// Latest [`ChangeHash`] (at the moment of issuing) of the [`super::super::identity::Identity`]
    /// this Purpose Key belongs to
    #[n(1)] pub subject_latest_change_hash: ChangeHash,
    /// Public key of this Purpose Key
    #[n(2)] pub public_key: PurposePublicKey,
    /// Creation [`TimestampInSeconds`] (UTC)
    #[n(3)] pub created_at: TimestampInSeconds,
    /// Expiration [`TimestampInSeconds`] (UTC)
    #[n(4)] pub expires_at: TimestampInSeconds,
}

/// [`PurposeKeyAttestation`]'s public key
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[rustfmt::skip]
pub enum PurposePublicKey {
    /// Key dedicated to creation of Secure Channels
    /// This key is used as a static key in Noise XX handshake
    #[n(0)] SecureChannelStaticKey(#[n(0)] X25519PublicKey),
    /// Key dedicated to signing [`super::Credential`]s
    #[n(1)] CredentialSigningKey(#[n(0)] CredentialSigningKey),
}

/// Key dedicated to signing [`super::Credential`]s
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[rustfmt::skip]
pub enum CredentialSigningKey {
    /// EdDSA Ed25519 Public Key
    #[n(0)] Ed25519PublicKey(#[n(0)] EdDSACurve25519PublicKey),
    /// ECDSA P256 Public Key
    #[n(1)] P256ECDSAPublicKey(#[n(0)] ECDSASHA256CurveP256PublicKey),
}
