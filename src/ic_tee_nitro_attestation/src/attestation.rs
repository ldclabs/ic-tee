use cbor2::from_slice;
use cose2::{iana, Error, Label, Sign1Message, Verifier};
use ring::signature::{VerificationAlgorithm, ECDSA_P384_SHA384_FIXED};
use sha2::Sha384;
use std::sync::LazyLock;
use x509_parser::{pem::Pem, prelude::*};

// https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md

use crate::Attestation;

const ALG_ES384: Label = Label::Int(iana::AlgorithmES384);

const ROOT_CERT_PEM: &[u8] = include_bytes!("./AWS_NitroEnclaves_Root-G1.pem");

static ROOT_CERT_PUBKEY: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut pems = Pem::iter_from_buffer(ROOT_CERT_PEM)
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse PEM buffer");
    let pem = pems.pop().expect("No PEM blocks found");
    let cert = pem.parse_x509().expect("Failed to parse X.509 certificate");
    cert.public_key().subject_public_key.as_ref().to_vec()
});

pub fn parse(attestation_doc: &[u8]) -> Result<(Sign1Message, Attestation), String> {
    let cs1 = Sign1Message::from_slice(attestation_doc)
        .map_err(|err| format!("invalid COSE sign1 token: {}", err))?;
    let attestation: Attestation = cs1
        .payload
        .as_ref()
        .map(|data| {
            from_slice(data.as_slice())
                .map_err(|err| format!("invalid attestation document: {:?}", err))
        })
        .ok_or_else(|| "no payload in COSE sign1 token".to_string())??;

    Ok((cs1, attestation))
}

pub fn parse_and_verify(attestation_doc: &[u8]) -> Result<Attestation, String> {
    let (cs1, doc) = parse(attestation_doc)?;
    verify(&cs1, &doc)?;
    Ok(doc)
}

/// Verifies the COSE signature of a parsed attestation document and its certificate chain,
/// including that every certificate is valid at the document's timestamp.
///
/// `doc` must be the payload that [`parse`] decoded from `cs1`.
pub fn verify(cs1: &Sign1Message, doc: &Attestation) -> Result<(), String> {
    let alg = cs1
        .protected
        .alg()
        .map_err(|err| format!("invalid COSE protected header: {}", err))?;
    if alg != Some(ALG_ES384) {
        return Err(format!("unsupported COSE algorithm: {:?}", alg));
    }

    // leaf certificate first, root certificate last
    let mut certs: Vec<X509Certificate> = Vec::with_capacity(doc.cabundle.len() + 1);
    certs.push(x509_cert(&doc.certificate)?);
    for pem in doc.cabundle.iter().rev() {
        certs.push(x509_cert(pem)?);
    }

    let at = ASN1Time::from_timestamp((doc.timestamp / 1000) as i64)
        .map_err(|err| format!("invalid attestation timestamp: {:?}", err))?;
    for cert in &certs {
        if !cert.validity().is_valid_at(at) {
            return Err(format!(
                "certificate {:?} is not valid at the attestation timestamp",
                cert.subject()
            ));
        }
    }

    let pub_key = certs[0].public_key();
    cs1.verify(&Es384Verifier(pub_key.subject_public_key.as_ref()), None)
        .map_err(|_| "signature verification failed".to_string())?;

    verify_cert_chain(&certs)
}

/// A [`Verifier`] for COSE_Sign1 documents signed with ECDSA P-384 / SHA-384,
/// wrapping the raw EC public key bytes from the leaf certificate.
struct Es384Verifier<'a>(&'a [u8]);

impl Verifier for Es384Verifier<'_> {
    fn alg(&self) -> Option<Label> {
        Some(ALG_ES384)
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        ECDSA_P384_SHA384_FIXED
            .verify(self.0.into(), data.into(), signature.into())
            .map_err(|_| Error::verify("signature verification failed"))
    }
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    use sha2::Digest;

    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn x509_cert(data: &[u8]) -> Result<X509Certificate<'_>, String> {
    let (_rem, x509) = X509Certificate::from_der(data)
        .map_err(|err| format!("invalid X.509 certificate: {:?}", err))?;
    Ok(x509)
}

pub fn verify_cert_chain(certs: &[X509Certificate]) -> Result<(), String> {
    let mut iter = certs.iter().peekable();
    while let Some(cert) = iter.next() {
        if let Some(next_cert) = iter.peek() {
            let issuer = cert.issuer();
            let subject = next_cert.subject();
            if issuer != subject {
                return Err(format!(
                    "certificate chain is broken: issuer {:?} != subject {:?}",
                    issuer, subject
                ));
            }
            cert.verify_signature(Some(next_cert.public_key()))
                .map_err(|err| {
                    format!(
                        "signature verification failed for certificate {:?}: {:?}",
                        cert.subject(),
                        err
                    )
                })?;
        } else if cert.public_key().subject_public_key.as_ref() != *ROOT_CERT_PUBKEY {
            return Err(format!(
                "certificate chain is broken: last certificate {:?} is not a root certificate",
                cert.subject()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // https://github.com/briansmith/ring/issues/1942
    // export C_INCLUDE_PATH="/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/:$C_INCLUDE_PATH"
    #[test]
    fn test_parse_and_verify() {
        let doc: &[u8] = include_bytes!("./test/attestation2.hex");
        let doc = hex::decode(doc).unwrap();
        let attestation = parse_and_verify(&doc).unwrap();
        println!("{:?}", attestation);
    }

    #[test]
    fn test_verify_rejects_expired_certificate() {
        let doc: &[u8] = include_bytes!("./test/attestation2.hex");
        let doc = hex::decode(doc).unwrap();
        let (cs1, mut attestation) = parse(&doc).unwrap();
        assert!(verify(&cs1, &attestation).is_ok());

        attestation.timestamp += 1000 * 3600 * 24 * 365;
        let err = verify(&cs1, &attestation).unwrap_err();
        assert!(err.contains("not valid at the attestation timestamp"));
    }
}
