use crate::CheckPoint;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::mem;
use std::sync::Arc;
use store::iter::AncestorRoots;
use store::Store;
use types::{EthSpec, Hash256, Slot};

// This is 5 epochs (on mainnet spec). As long as the chain is finalizaing as expected, we should
// usually not need to read the database when pruning the head blocks.
pub const INITIAL_ANCESTORS: usize = 64 * 5;

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    SlotTooHigh { slot: Slot, head: Slot },
    UnableToCreateAncestorRoots,
}

pub struct AncestorAccumulator<E: EthSpec, U: Store<E>> {
    block_roots: AncestorRoots<E, U>,
    store: Arc<U>,
    ancestors: HashSet<Hash256>,
    lowest_slot: Slot,
    head: (Hash256, Slot),
    _phantom: PhantomData<E>,
}

impl<E: EthSpec, U: Store<E>> AncestorAccumulator<E, U> {
    pub fn new(store: Arc<U>, head: &CheckPoint<E>) -> Result<Self, Error> {
        let block_roots =
            AncestorRoots::block_roots(store.clone(), &head.beacon_state, INITIAL_ANCESTORS)
                .ok_or_else(|| Error::UnableToCreateAncestorRoots)?;

        Ok(Self {
            block_roots,
            store,
            ancestors: HashSet::new(),
            lowest_slot: head.beacon_block.slot,
            head: (head.beacon_block_root, head.beacon_block.slot),
            _phantom: PhantomData,
        })
    }

    pub fn contains(&mut self, block_root: Hash256, block_slot: Slot) -> Result<bool, Error> {
        let (head_root, head_slot) = self.head;

        if block_slot > head_slot {
            Err(Error::SlotTooHigh {
                slot: block_slot,
                head: self.head.1,
            })
        } else if block_root == head_root {
            // We declare that the head block is an ancestor of itself. This seems a bit odd but it
            // suits our purpose.
            Ok(true)
        } else if block_slot >= self.lowest_slot {
            Ok(self.ancestors.contains(&block_root))
        } else {
            // The use of `mem::replace` is to satisfy the borrow checker.
            //
            // `AncestorRoots::iter(..)` requires a mutable reference, so we can't iterate with it
            // whilst it's attached to self _and_ mutate other components of self at the same time.
            let mut block_roots = mem::replace(
                &mut self.block_roots,
                AncestorRoots::empty(self.store.clone()),
            );

            let is_ancestor = block_roots
                .iter()
                .take_while(|(_, slot)| *slot >= block_slot)
                .inspect(|(root, slot)| {
                    self.ancestors.insert(*root);
                    self.lowest_slot = *slot;
                })
                .any(|(root, slot)| root == block_root && slot == block_slot);

            mem::replace(&mut self.block_roots, block_roots);

            Ok(is_ancestor)
        }
    }
}
