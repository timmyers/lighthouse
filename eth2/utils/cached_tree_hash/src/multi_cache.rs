use crate::{int_log, CachedTreeHash, Error, Hash256, TreeHashCache};
use ssz::{Decode, Encode, SszBytes};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::Unsigned, VariableList};
use tree_hash::mix_in_length;

/// Multi-level tree hash cache.
///
/// Suitable for lists/vectors/containers holding values which themselves have caches.
///
/// Note: this cache could be made composable by replacing the hardcoded `Vec<TreeHashCache>` with
/// `Vec<C>`, allowing arbitrary nesting, but for now we stick to 2-level nesting because that's all
/// we need.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct MultiTreeHashCache {
    list_cache: TreeHashCache,
    value_caches: Vec<TreeHashCache>,
}

impl<T, N> CachedTreeHash<MultiTreeHashCache> for VariableList<T, N>
where
    T: CachedTreeHash<TreeHashCache>,
    N: Unsigned,
{
    fn new_tree_hash_cache() -> MultiTreeHashCache {
        MultiTreeHashCache {
            list_cache: TreeHashCache::new(int_log(N::to_usize())),
            value_caches: vec![],
        }
    }

    fn recalculate_tree_hash_root(&self, cache: &mut MultiTreeHashCache) -> Result<Hash256, Error> {
        if self.len() < cache.value_caches.len() {
            return Err(Error::CannotShrink);
        }

        // Resize the value caches to the size of the list.
        cache
            .value_caches
            .resize(self.len(), T::new_tree_hash_cache());

        // Update all individual value caches.
        self.iter()
            .zip(cache.value_caches.iter_mut())
            .try_for_each(|(value, cache)| value.recalculate_tree_hash_root(cache).map(|_| ()))?;

        // Pipe the value roots into the list cache, then mix in the length.
        // Note: it's possible to avoid this 2nd iteration (or an allocation) by using
        // `itertools::process_results`, but it requires removing the `ExactSizeIterator`
        // bound from `recalculate_merkle_root`, and only saves about 5% in benchmarks.
        let list_root = cache.list_cache.recalculate_merkle_root(
            cache
                .value_caches
                .iter()
                .map(|value_cache| value_cache.root().to_fixed_bytes()),
        )?;

        Ok(Hash256::from_slice(&mix_in_length(
            list_root.as_bytes(),
            self.len(),
        )))
    }
}

impl MultiTreeHashCache {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let container = SszContainer::from_ssz_bytes(bytes).map_err(|e| Error::BytesInvalid(e))?;

        container.into_multi_cache()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        SszContainer::from_multi_cache(self).as_ssz_bytes()
    }
}

/// A helper struct for more efficient SSZ encoding/decoding.
#[derive(Encode, Decode)]
struct SszContainer {
    list_cache: SszBytes,
    value_caches: Vec<SszBytes>,
}

impl SszContainer {
    fn from_multi_cache(cache: &MultiTreeHashCache) -> SszContainer {
        SszContainer {
            list_cache: SszBytes(cache.list_cache.as_bytes()),
            value_caches: cache
                .value_caches
                .iter()
                .map(|vc| SszBytes(vc.as_bytes()))
                .collect(),
        }
    }

    fn into_multi_cache(self) -> Result<MultiTreeHashCache, Error> {
        Ok(MultiTreeHashCache {
            list_cache: TreeHashCache::from_bytes(&self.list_cache.0)?,
            value_caches: self
                .value_caches
                .iter()
                .map(|ssz_bytes| TreeHashCache::from_bytes(&ssz_bytes.0))
                .collect::<Result<_, _>>()?,
        })
    }
}
