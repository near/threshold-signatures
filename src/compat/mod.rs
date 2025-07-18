
#[cfg(test)]
mod test_scalar_hash {
    use elliptic_curve::{ops::Reduce, Curve, CurveArithmetic};

    use digest::{Digest, FixedOutput};
    use ecdsa::hazmat::DigestPrimitive;
    use k256::{FieldBytes, Scalar, Secp256k1};

    #[cfg(test)]
    pub(crate) fn scalar_hash(msg: &[u8]) -> <Secp256k1 as CurveArithmetic>::Scalar {
        let digest = <Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(msg);
        let m_bytes: FieldBytes = digest.finalize_fixed();
        <Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&m_bytes)
    }
}

#[cfg(test)]
pub(crate) use test_scalar_hash::scalar_hash;
