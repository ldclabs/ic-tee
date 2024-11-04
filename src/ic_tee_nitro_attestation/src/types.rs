use candid::CandidType;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

#[derive(CandidType, Debug, Serialize, Deserialize, Copy, Clone, PartialEq)]
pub enum Digest {
    /// SHA256
    SHA256,
    /// SHA384
    SHA384,
    /// SHA512
    SHA512,
}

/// An attestation response.  This is also used for sealing data.
#[derive(CandidType, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Attestation {
    /// Issuing NSM ID
    pub module_id: String,

    /// The digest function used for calculating the register values
    /// Can be: "SHA256" | "SHA512"
    pub digest: Digest,

    /// UTC time when document was created expressed as milliseconds since Unix Epoch
    pub timestamp: u64,

    /// Map of all locked PCRs at the moment the attestation document was generated
    pub pcrs: BTreeMap<usize, ByteBuf>,

    /// The infrastucture certificate used to sign the document, DER encoded
    pub certificate: ByteBuf,
    /// Issuing CA bundle for infrastructure certificate
    pub cabundle: Vec<ByteBuf>,

    /// An optional DER-encoded key the attestation consumer can use to encrypt data with
    pub public_key: Option<ByteBuf>,

    /// Additional signed user data, as defined by protocol.
    pub user_data: Option<ByteBuf>,

    /// An optional cryptographic nonce provided by the attestation consumer as a proof of
    /// authenticity.
    pub nonce: Option<ByteBuf>,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AttestationRequest {
    pub public_key: Option<ByteBuf>,
    pub user_data: Option<ByteBuf>,
    pub nonce: Option<ByteBuf>,
}
