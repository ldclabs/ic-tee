use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
use ic_cose_types::BoxError;
use ic_tee_nitro_attestation::AttestationRequest;
use std::sync::LazyLock;

// The NSM device is opened once and shared, the driver serializes concurrent requests.
static NSM_FD: LazyLock<i32> = LazyLock::new(nsm_driver::nsm_init);

/// Requests an attestation document from the Nitro Secure Module.
/// The blocking NSM call runs on the blocking thread pool.
pub async fn sign_attestation(req: AttestationRequest) -> Result<Vec<u8>, BoxError> {
    tokio::task::spawn_blocking(move || nsm_attestation(req)).await?
}

fn nsm_attestation(req: AttestationRequest) -> Result<Vec<u8>, BoxError> {
    let nsm_fd = *NSM_FD;
    if nsm_fd < 0 {
        Err("failed to open Nitro secure module".to_string())?;
    }

    let request = Request::Attestation {
        public_key: req.public_key.map(|v| v.0.into()),
        user_data: req.user_data.map(|v| v.0.into()),
        nonce: req.nonce.map(|v| v.0.into()),
    };

    match nsm_driver::nsm_process_request(nsm_fd, request) {
        Response::Attestation { document } => Ok(document),
        other => Err(format!("invalid Nitro attestation response: {:?}", other).into()),
    }
}
