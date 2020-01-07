use super::{PublicKey, RawPublicKey};

/// A BLS aggregate public key.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, Clone, Default)]
pub struct AggregatePublicKey(RawPublicKey);

impl AggregatePublicKey {
    pub fn new() -> Self {
        AggregatePublicKey(Default::default())
    }

    pub fn new_from_raw(pk: RawPublicKey) -> Self {
        AggregatePublicKey(pk)
    }

    pub fn add(&mut self, public_key: &PublicKey) {
        self.0.add_assign(public_key.as_raw())
    }

    pub fn add_point(&mut self, point: &RawPublicKey) {
        self.0.add_assign(point)
    }

    /// Returns the underlying public key.
    pub fn as_raw(&self) -> &RawPublicKey {
        &self.0
    }

    pub fn into_raw(self) -> RawPublicKey {
        self.0
    }

    /// Return a hex string representation of this key's bytes.
    #[cfg(test)]
    pub fn as_hex_string(&self) -> String {
        serde_hex::encode(&self.as_raw().serialize())
    }
}
