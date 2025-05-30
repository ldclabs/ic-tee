use candid::CandidType;
use ic_auth_types::ByteBufB64;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(CandidType, Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub enum Digest {
    /// SHA256
    SHA256,
    /// SHA384
    #[default]
    SHA384,
    /// SHA512
    SHA512,
}

/// An attestation response.  This is also used for sealing data.
#[derive(CandidType, Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct Attestation {
    /// Issuing NSM ID
    pub module_id: String,

    /// The digest function used for calculating the register values
    /// Can be: "SHA256" | "SHA512"
    pub digest: Digest,

    /// UTC time when document was created expressed as milliseconds since Unix Epoch
    pub timestamp: u64,

    /// Map of all locked PCRs at the moment the attestation document was generated
    pub pcrs: BTreeMap<usize, ByteBufB64>,

    /// The infrastucture certificate used to sign the document, DER encoded
    pub certificate: ByteBufB64,
    /// Issuing CA bundle for infrastructure certificate
    pub cabundle: Vec<ByteBufB64>,

    /// An optional DER-encoded key the attestation consumer can use to encrypt data with
    pub public_key: Option<ByteBufB64>,

    /// Additional signed user data, as defined by protocol.
    pub user_data: Option<ByteBufB64>,

    /// An optional cryptographic nonce provided by the attestation consumer as a proof of
    /// authenticity.
    pub nonce: Option<ByteBufB64>,
}

#[derive(CandidType, Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct AttestationRequest {
    pub public_key: Option<ByteBufB64>,
    pub user_data: Option<ByteBufB64>,
    pub nonce: Option<ByteBufB64>,
}
