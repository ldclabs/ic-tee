use ciborium::from_reader;
use coset::{iana, Algorithm, CborSerializable, CoseSign1};
use lazy_static::lazy_static;
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::Sha384;
use x509_parser::prelude::*;

// https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md

use crate::Attestation;

const SIGN1_TAG_PREFIX: &[u8] = &[0xd2]; // COSE_Sign1 Tag 18
const ALG_ES384: Algorithm = Algorithm::Assigned(iana::Algorithm::ES384);

static ROOT_CERT_PEM: &[u8] = include_bytes!("./AWS_NitroEnclaves_Root-G1.pem");

lazy_static! {
    static ref ROOT_CERT: X509Certificate<'static> = x509_cert(ROOT_CERT_PEM).unwrap();
}

pub fn parse(attestation_doc: &[u8]) -> Result<(CoseSign1, Attestation), String> {
    let cs1 = CoseSign1::from_slice(if attestation_doc.starts_with(SIGN1_TAG_PREFIX) {
        &attestation_doc[1..]
    } else {
        attestation_doc
    })
    .map_err(|err| format!("invalid COSE sign1 token: {}", err))?;
    let attestation: Attestation = cs1
        .payload
        .as_ref()
        .map(|data| {
            from_reader(data.as_slice())
                .map_err(|err| format!("invalid attestation document: {:?}", err))
        })
        .ok_or_else(|| "no payload in COSE sign1 token".to_string())??;

    Ok((cs1, attestation))
}

pub fn parse_and_verify(attestation_doc: &[u8]) -> Result<Attestation, String> {
    let (cs1, doc) = parse(attestation_doc)?;
    if cs1.protected.header.alg != Some(ALG_ES384) {
        return Err(format!(
            "unsupported COSE algorithm: {:?}",
            cs1.protected.header.alg
        ));
    }
    let sig = Signature::from_der(&cs1.signature)
        .map_err(|err| format!("invalid signature: {:?}", err))?;
    let cert = x509_cert(&doc.certificate)?;
    let pub_key = cert.public_key();
    let verifying_key = VerifyingKey::from_sec1_bytes(pub_key.raw)
        .map_err(|err| format!("invalid public key in X.509 certificate: {:?}", err))?;
    let msg = cs1.tbs_data(&[]);
    verifying_key
        .verify(&sha384(&msg), &sig)
        .map_err(|err| format!("signature verification failed: {:?}", err))?;

    let mut certs: Vec<X509Certificate> = Vec::with_capacity(doc.cabundle.len());
    for pem in &doc.cabundle {
        let cert = x509_cert(pem)?;
        certs.push(cert);
    }
    certs.push(cert);
    certs.reverse();
    verify_cert_chain(&certs)?;

    Ok(doc)
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    use sha2::Digest;

    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn x509_cert(data: &[u8]) -> Result<X509Certificate, String> {
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
        } else if cert.public_key() != ROOT_CERT.public_key() {
            return Err(format!(
                "certificate chain is broken: last certificate {:?} is not a root certificate",
                cert.subject()
            ));
        }
    }
    Ok(())
}
