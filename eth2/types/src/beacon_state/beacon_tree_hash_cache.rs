use super::Error;
use cached_tree_hash::{MultiTreeHashCache, TreeHashCache};
use ssz::{Decode, Encode, SszBytes};
use ssz_derive::{Decode, Encode};

#[derive(Debug, PartialEq, Clone, Default)]
pub struct BeaconTreeHashCache {
    pub(crate) initialized: bool,
    pub(crate) block_roots: TreeHashCache,
    pub(crate) state_roots: TreeHashCache,
    pub(crate) historical_roots: TreeHashCache,
    pub(crate) validators: MultiTreeHashCache,
    pub(crate) balances: TreeHashCache,
    pub(crate) randao_mixes: TreeHashCache,
    pub(crate) slashings: TreeHashCache,
}

impl BeaconTreeHashCache {
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let container = SszContainer::from_ssz_bytes(bytes)
            .map_err(|e| Error::CachedTreeHashError(cached_tree_hash::Error::BytesInvalid(e)))?;

        container.into_cache()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        SszContainer::from_cache(self).as_ssz_bytes()
    }
}

/// A helper struct for more efficient SSZ encoding/decoding.
#[derive(Encode, Decode)]
struct SszContainer {
    initialized: bool,
    block_roots: SszBytes,
    state_roots: SszBytes,
    historical_roots: SszBytes,
    validators: SszBytes,
    balances: SszBytes,
    randao_mixes: SszBytes,
    slashings: SszBytes,
}

impl SszContainer {
    fn from_cache(cache: &BeaconTreeHashCache) -> SszContainer {
        SszContainer {
            initialized: cache.initialized,
            block_roots: SszBytes(cache.block_roots.as_bytes()),
            state_roots: SszBytes(cache.state_roots.as_bytes()),
            historical_roots: SszBytes(cache.historical_roots.as_bytes()),
            validators: SszBytes(cache.validators.as_bytes()),
            balances: SszBytes(cache.balances.as_bytes()),
            randao_mixes: SszBytes(cache.randao_mixes.as_bytes()),
            slashings: SszBytes(cache.slashings.as_bytes()),
        }
    }

    fn into_cache(self) -> Result<BeaconTreeHashCache, Error> {
        Ok(BeaconTreeHashCache {
            initialized: self.initialized,
            block_roots: TreeHashCache::from_bytes(&self.block_roots.0)?,
            state_roots: TreeHashCache::from_bytes(&self.state_roots.0)?,
            historical_roots: TreeHashCache::from_bytes(&self.historical_roots.0)?,
            validators: MultiTreeHashCache::from_bytes(&self.validators.0)?,
            balances: TreeHashCache::from_bytes(&self.balances.0)?,
            randao_mixes: TreeHashCache::from_bytes(&self.randao_mixes.0)?,
            slashings: TreeHashCache::from_bytes(&self.slashings.0)?,
        })
    }
}
