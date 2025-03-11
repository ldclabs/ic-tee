use http::header::HeaderName;

mod content;

pub use content::*;

pub static HEADER_X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
pub static HEADER_X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
pub static HEADER_X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

/// TEE ID added to upstream requests
pub static HEADER_IC_TEE_ID: HeaderName = HeaderName::from_static("ic-tee-id");
/// TEE instance ID added to upstream requests
pub static HEADER_IC_TEE_INSTANCE: HeaderName = HeaderName::from_static("ic-tee-instance");
