use crate::VerifyingPublicKey;

impl VerifyingPublicKey {
    /// If key is of EdDSACurve25519 type.
    pub fn is_eddsa_curve25519(&self) -> bool {
        match self {
            VerifyingPublicKey::EdDSACurve25519(_) => true,
            VerifyingPublicKey::ECDSASHA256CurveP256(_) => false,
        }
    }

    /// If key is of ECDSASHA256CurveP256 type.
    pub fn is_ecdsa_sha256_curve_p256(&self) -> bool {
        match self {
            VerifyingPublicKey::EdDSACurve25519(_) => false,
            VerifyingPublicKey::ECDSASHA256CurveP256(_) => true,
        }
    }
}
