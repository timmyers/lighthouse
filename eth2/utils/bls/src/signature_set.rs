use bls_eth_rust::HASH_SIZE;
use crate::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};
use super::{RawPublicKey, RawSignature};
use std::borrow::Cow;

type Message = Vec<u8>;
type Domain = u64;

#[derive(Clone, Debug)]
pub struct SignedMessage<'a> {
    pub signing_keys: Vec<Cow<'a, RawPublicKey>>,
    message: Message,
}

impl<'a> SignedMessage<'a> {
    pub fn new(signing_keys: Vec<Cow<'a, RawPublicKey>>, message: Message) -> Self {
        Self {
            signing_keys,
            message,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignatureSet<'a> {
    pub signature: &'a RawSignature,
    signed_messages: Vec<SignedMessage<'a>>,
    domain: Domain,
}

impl<'a> SignatureSet<'a> {
    pub fn single<S>(
        signature: &'a S,
        signing_key: Cow<'a, RawPublicKey>,
        message: Message,
        domain: Domain,
    ) -> Self
    where
        S: G2Ref,
    {
        Self {
            signature: signature.g2_ref(),
            signed_messages: vec![SignedMessage::new(vec![signing_key], message)],
            domain,
        }
    }

    pub fn dual<S, T>(
        signature: &'a S,
        message_0: Message,
        message_0_signing_keys: Vec<Cow<'a, RawPublicKey>>,
        message_1: Message,
        message_1_signing_keys: Vec<Cow<'a, RawPublicKey>>,
        domain: Domain,
    ) -> Self
    where
        T: G1Ref + Clone,
        S: G2Ref,
    {
        Self {
            signature: signature.g2_ref(),
            signed_messages: vec![
                SignedMessage::new(message_0_signing_keys, message_0),
                SignedMessage::new(message_1_signing_keys, message_1),
            ],
            domain,
        }
    }

    pub fn new<S>(signature: &'a S, signed_messages: Vec<SignedMessage<'a>>, domain: Domain) -> Self
    where
        S: G2Ref,
    {
        Self {
            signature: signature.g2_ref(),
            signed_messages,
            domain,
        }
    }

    pub fn is_valid(&self) -> bool {
        let sig = AggregateSignature::from_point(self.signature.clone());

        let mut messages: Vec<Vec<u8>> = vec![];
        let mut pubkeys = vec![];

        self.signed_messages.iter().for_each(|signed_message| {
            messages.push(signed_message.message.clone());

            let point = if signed_message.signing_keys.len() == 1 {
                signed_message.signing_keys[0].clone().into_owned()
            } else {
                aggregate_public_keys(&signed_message.signing_keys).into_raw()
            };

            pubkeys.push(AggregatePublicKey::new_from_raw(point));
        });

        let pubkey_refs: Vec<&AggregatePublicKey> =
            pubkeys.iter().map(std::borrow::Borrow::borrow).collect();

        let message_refs: Vec<&[u8]> =
            messages.iter().map(std::borrow::Borrow::borrow).collect();

        sig.verify_multiple(&message_refs, self.domain, &pubkey_refs)
    }
}

#[cfg(not(feature = "fake_crypto"))]
pub fn verify_signature_sets<'a>(iter: impl Iterator<Item = SignatureSet<'a>>) -> bool {
    for set in iter {
        if !set.is_valid() {
            return false;
        }
    }
    true
}

#[cfg(feature = "fake_crypto")]
pub fn verify_signature_sets<'a>(_iter: impl Iterator<Item = SignatureSet<'a>>) -> bool {
    true
}

type VerifySet<'a> = (RawSignature, Vec<RawPublicKey>, Vec<Vec<u8>>, u64);

impl<'a> Into<VerifySet<'a>> for SignatureSet<'a> {
    fn into(self) -> VerifySet<'a> {
        let signature = self.signature.clone();

        let (pubkeys, messages): (Vec<RawPublicKey>, Vec<Message>) = self
            .signed_messages
            .into_iter()
            .map(|signed_message| {
                let key = if signed_message.signing_keys.len() == 1 {
                    signed_message.signing_keys[0].clone().into_owned()
                } else {
                    aggregate_public_keys(&signed_message.signing_keys).into_raw()
                };

                (key, signed_message.message)
            })
            .unzip();

        (signature, pubkeys, messages, self.domain)
    }
}

/// Create an aggregate public key for a list of validators, failing if any key can't be found.
fn aggregate_public_keys<'a>(public_keys: &'a [Cow<'a, RawPublicKey>]) -> AggregatePublicKey {
    public_keys
        .iter()
        .fold(AggregatePublicKey::new(), |mut aggregate, pubkey| {
            aggregate.add_point(&pubkey);
            aggregate
        })
}

pub trait G1Ref {
    fn g1_ref<'a>(&'a self) -> Cow<'a, RawPublicKey>;
}

impl G1Ref for AggregatePublicKey {
    fn g1_ref<'a>(&'a self) -> Cow<'a, RawPublicKey> {
        Cow::Borrowed(&self.as_raw())
    }
}

impl G1Ref for PublicKey {
    fn g1_ref<'a>(&'a self) -> Cow<'a, RawPublicKey> {
        Cow::Borrowed(&self.as_raw())
    }
}

pub trait G2Ref {
    fn g2_ref(&self) -> &RawSignature;
}

impl G2Ref for AggregateSignature {
    fn g2_ref(&self) -> &RawSignature {
        &self.as_raw()
    }
}

impl G2Ref for Signature {
    fn g2_ref(&self) -> &RawSignature {
        &self.as_raw()
    }
}
