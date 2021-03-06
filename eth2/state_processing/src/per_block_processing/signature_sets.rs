//! A `SignatureSet` is an abstraction over the components of a signature. A `SignatureSet` may be
//! validated individually, or alongside in others in a potentially cheaper bulk operation.
//!
//! This module exposes one function to extract each type of `SignatureSet` from a `BeaconBlock`.
use bls::{G1Point, G1Ref, SignatureSet, SignedMessage};
use std::borrow::Cow;
use std::convert::TryInto;
use tree_hash::TreeHash;
use types::{
    AggregateSignature, AttesterSlashing, BeaconBlock, BeaconState, BeaconStateError, ChainSpec,
    DepositData, Domain, EthSpec, Hash256, IndexedAttestation, ProposerSlashing, PublicKey,
    Signature, SignedBeaconBlock, SignedBeaconBlockHeader, SignedRoot, SignedVoluntaryExit,
    SigningRoot,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// Signature verification failed. The block is invalid.
    SignatureInvalid,
    /// There was an error attempting to read from a `BeaconState`. Block
    /// validity was not determined.
    BeaconStateError(BeaconStateError),
    /// Attempted to find the public key of a validator that does not exist. You cannot distinguish
    /// between an error and an invalid block in this case.
    ValidatorUnknown(u64),
    /// The public keys supplied do not match the number of objects requiring keys. Block validity
    /// was not determined.
    MismatchedPublicKeyLen { pubkey_len: usize, other_len: usize },
    /// The public key bytes stored in the `BeaconState` were not valid. This is a serious internal
    /// error.
    BadBlsBytes { validator_index: u64 },
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

/// A signature set that is valid if a block was signed by the expected block producer.
pub fn block_proposal_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    signed_block: &'a SignedBeaconBlock<T>,
    block_root: Option<Hash256>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let block = &signed_block.message;
    let proposer_index = state.get_beacon_proposer_index(block.slot, spec)?;

    let domain = spec.get_domain(
        block.slot.epoch(T::slots_per_epoch()),
        Domain::BeaconProposer,
        &state.fork,
    );

    let message = if let Some(root) = block_root {
        SigningRoot {
            object_root: root,
            domain,
        }
        .tree_hash_root()
    } else {
        block.signing_root(domain).as_bytes().to_vec()
    };

    Ok(SignatureSet::single(
        &signed_block.signature,
        validator_pubkey(state, proposer_index)?,
        message,
    ))
}

/// A signature set that is valid if the block proposers randao reveal signature is correct.
pub fn randao_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    block: &'a BeaconBlock<T>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let proposer_index = state.get_beacon_proposer_index(block.slot, spec)?;

    let domain = spec.get_domain(
        block.slot.epoch(T::slots_per_epoch()),
        Domain::Randao,
        &state.fork,
    );

    let message = state.current_epoch().signing_root(domain);

    Ok(SignatureSet::single(
        &block.body.randao_reveal,
        validator_pubkey(state, proposer_index)?,
        message.as_bytes().to_vec(),
    ))
}

/// Returns two signature sets, one for each `BlockHeader` included in the `ProposerSlashing`.
pub fn proposer_slashing_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    proposer_slashing: &'a ProposerSlashing,
    spec: &'a ChainSpec,
) -> Result<(SignatureSet<'a>, SignatureSet<'a>)> {
    let proposer_index = proposer_slashing.proposer_index as usize;

    Ok((
        block_header_signature_set(
            state,
            &proposer_slashing.signed_header_1,
            validator_pubkey(state, proposer_index)?,
            spec,
        )?,
        block_header_signature_set(
            state,
            &proposer_slashing.signed_header_2,
            validator_pubkey(state, proposer_index)?,
            spec,
        )?,
    ))
}

/// Returns a signature set that is valid if the given `pubkey` signed the `header`.
fn block_header_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    signed_header: &'a SignedBeaconBlockHeader,
    pubkey: Cow<'a, G1Point>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let domain = spec.get_domain(
        signed_header.message.slot.epoch(T::slots_per_epoch()),
        Domain::BeaconProposer,
        &state.fork,
    );

    let message = signed_header
        .message
        .signing_root(domain)
        .as_bytes()
        .to_vec();

    Ok(SignatureSet::single(
        &signed_header.signature,
        pubkey,
        message,
    ))
}

/// Returns the signature set for the given `indexed_attestation`.
pub fn indexed_attestation_signature_set<'a, 'b, T: EthSpec>(
    state: &'a BeaconState<T>,
    signature: &'a AggregateSignature,
    indexed_attestation: &'b IndexedAttestation<T>,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let pubkeys = indexed_attestation
        .attesting_indices
        .into_iter()
        .map(|&validator_idx| Ok(validator_pubkey(state, validator_idx as usize)?))
        .collect::<Result<_>>()?;

    let domain = spec.get_domain(
        indexed_attestation.data.target.epoch,
        Domain::BeaconAttester,
        &state.fork,
    );

    let message = indexed_attestation.data.signing_root(domain);
    let signed_message = SignedMessage::new(pubkeys, message.as_bytes().to_vec());

    Ok(SignatureSet::new(signature, vec![signed_message]))
}

/// Returns the signature set for the given `attester_slashing` and corresponding `pubkeys`.
pub fn attester_slashing_signature_sets<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    attester_slashing: &'a AttesterSlashing<T>,
    spec: &'a ChainSpec,
) -> Result<(SignatureSet<'a>, SignatureSet<'a>)> {
    Ok((
        indexed_attestation_signature_set(
            state,
            &attester_slashing.attestation_1.signature,
            &attester_slashing.attestation_1,
            spec,
        )?,
        indexed_attestation_signature_set(
            state,
            &attester_slashing.attestation_2.signature,
            &attester_slashing.attestation_2,
            spec,
        )?,
    ))
}

/// Returns the BLS values in a `Deposit`, if they're all valid. Otherwise, returns `None`.
///
/// This method is separate to `deposit_signature_set` to satisfy lifetime requirements.
pub fn deposit_pubkey_signature_message(
    deposit_data: &DepositData,
    spec: &ChainSpec,
) -> Option<(PublicKey, Signature, Vec<u8>)> {
    let pubkey = (&deposit_data.pubkey).try_into().ok()?;
    let signature = (&deposit_data.signature).try_into().ok()?;
    let domain = spec.get_deposit_domain();
    let message = deposit_data
        .as_deposit_message()
        .signing_root(domain)
        .as_bytes()
        .to_vec();
    Some((pubkey, signature, message))
}

/// Returns the signature set for some set of deposit signatures, made with
/// `deposit_pubkey_signature_message`.
pub fn deposit_signature_set<'a>(
    pubkey_signature_message: &'a (PublicKey, Signature, Vec<u8>),
) -> SignatureSet<'a> {
    let (pubkey, signature, message) = pubkey_signature_message;

    // Note: Deposits are valid across forks, thus the deposit domain is computed
    // with the fork zeroed.
    SignatureSet::single(signature, pubkey.g1_ref(), message.clone())
}

/// Returns a signature set that is valid if the `SignedVoluntaryExit` was signed by the indicated
/// validator.
pub fn exit_signature_set<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    signed_exit: &'a SignedVoluntaryExit,
    spec: &'a ChainSpec,
) -> Result<SignatureSet<'a>> {
    let exit = &signed_exit.message;
    let proposer_index = exit.validator_index as usize;

    let domain = spec.get_domain(exit.epoch, Domain::VoluntaryExit, &state.fork);

    let message = exit.signing_root(domain).as_bytes().to_vec();

    Ok(SignatureSet::single(
        &signed_exit.signature,
        validator_pubkey(state, proposer_index)?,
        message,
    ))
}

/// Maps a validator index to a `PublicKey`.
pub fn validator_pubkey<'a, T: EthSpec>(
    state: &'a BeaconState<T>,
    validator_index: usize,
) -> Result<Cow<'a, G1Point>> {
    let pubkey_bytes = &state
        .validators
        .get(validator_index)
        .ok_or_else(|| Error::ValidatorUnknown(validator_index as u64))?
        .pubkey;

    if let Some(pubkey) = pubkey_bytes.decompressed() {
        Ok(Cow::Borrowed(&pubkey.as_raw().point))
    } else {
        pubkey_bytes
            .try_into()
            .map(|pubkey: PublicKey| Cow::Owned(pubkey.as_raw().point.clone()))
            .map_err(|_| Error::BadBlsBytes {
                validator_index: validator_index as u64,
            })
    }
}
