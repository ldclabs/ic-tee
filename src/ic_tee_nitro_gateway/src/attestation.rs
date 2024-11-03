use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
use ic_tee_nitro_attestation::AttestationRequest;

pub fn sign_attestation(req: AttestationRequest) -> Result<Vec<u8>, String> {
    let request = Request::Attestation {
        public_key: req.public_key,
        user_data: req.user_data,
        nonce: req.nonce,
    };

    let nsm_fd = nsm_driver::nsm_init();
    if nsm_fd < 0 {
        Err("failed to open Nitro secure module".to_string())?;
    }

    let response = nsm_driver::nsm_process_request(nsm_fd, request);
    nsm_driver::nsm_exit(nsm_fd);

    match response {
        Response::Attestation { document } => Ok(document),
        other => Err(format!("invalid Nitro attestation response: {:?}", other)),
    }
}
