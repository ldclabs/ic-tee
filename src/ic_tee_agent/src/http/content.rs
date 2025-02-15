use axum_core::{
    extract::{FromRequest, Request},
    response::{IntoResponse, Response},
};
use bytes::{BufMut, Bytes, BytesMut};
use http::{
    header::{self, HeaderMap, HeaderValue},
    StatusCode,
};
use ic_cose_types::cose::sha3_256;
use serde::{de::DeserializeOwned, Serialize};

pub static CONTENT_TYPE_CBOR: &str = "application/cbor";
pub static CONTENT_TYPE_JSON: &str = "application/json";
pub static CONTENT_TYPE_TEXT: &str = "text/plain";
pub enum Content<T> {
    JSON(T, Option<StatusCode>),
    CBOR(T, Option<StatusCode>),
    Text(String, Option<StatusCode>),
    Other(String, Option<StatusCode>),
}

/// extract content with SHA3 hash from request body
pub enum ContentWithSHA3<T> {
    JSON(T, [u8; 32]),
    CBOR(T, [u8; 32]),
}

impl Content<()> {
    pub fn from(headers: &HeaderMap<HeaderValue>) -> Self {
        if let Some(accept) = headers.get(header::ACCEPT) {
            if let Ok(accept) = accept.to_str() {
                if accept.contains(CONTENT_TYPE_CBOR) {
                    return Content::CBOR((), None);
                }
                if accept.contains(CONTENT_TYPE_JSON) {
                    return Content::JSON((), None);
                }
                if accept.contains(CONTENT_TYPE_TEXT) {
                    return Content::Text("".to_string(), None);
                }
                return Content::Other(accept.to_string(), None);
            }
        }

        Content::Other("unknown".to_string(), None)
    }

    pub fn from_content_type(headers: &HeaderMap) -> Self {
        if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
            if let Ok(content_type) = content_type.to_str() {
                if let Ok(mime) = content_type.parse::<mime::Mime>() {
                    if mime.type_() == "application" {
                        if mime.subtype() == "cbor"
                            || mime.suffix().map_or(false, |name| name == "cbor")
                        {
                            return Content::CBOR((), None);
                        } else if mime.subtype() == "json"
                            || mime.suffix().map_or(false, |name| name == "json")
                        {
                            return Content::JSON((), None);
                        }
                    }
                }
            }
        }

        Content::Other("unknown".to_string(), None)
    }
}

impl<S, T> FromRequest<S> for Content<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Content::from_content_type(req.headers()) {
            Content::JSON(_, _) => {
                let body = Bytes::from_request(req, state)
                    .await
                    .map_err(IntoResponse::into_response)?;
                let value: T = serde_json::from_slice(&body).map_err(|err| {
                    Content::Text::<String>(err.to_string(), Some(StatusCode::BAD_REQUEST))
                        .into_response()
                })?;
                Ok(Self::JSON(value, None))
            }
            Content::CBOR(_, _) => {
                let body = Bytes::from_request(req, state)
                    .await
                    .map_err(IntoResponse::into_response)?;
                let value: T = ciborium::from_reader(&body[..]).map_err(|err| {
                    Content::Text::<String>(err.to_string(), Some(StatusCode::BAD_REQUEST))
                        .into_response()
                })?;
                Ok(Self::CBOR(value, None))
            }
            _ => Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()),
        }
    }
}

impl<S, T> FromRequest<S> for ContentWithSHA3<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Content::from_content_type(req.headers()) {
            Content::JSON(_, _) => {
                let body = Bytes::from_request(req, state)
                    .await
                    .map_err(IntoResponse::into_response)?;
                let value: T = serde_json::from_slice(&body).map_err(|err| {
                    Content::Text::<String>(err.to_string(), Some(StatusCode::BAD_REQUEST))
                        .into_response()
                })?;
                let hash = sha3_256(&body);
                Ok(Self::JSON(value, hash))
            }
            Content::CBOR(_, _) => {
                let body = Bytes::from_request(req, state)
                    .await
                    .map_err(IntoResponse::into_response)?;
                let value: T = ciborium::from_reader(&body[..]).map_err(|err| {
                    Content::Text::<String>(err.to_string(), Some(StatusCode::BAD_REQUEST))
                        .into_response()
                })?;
                let hash = sha3_256(&body);
                Ok(Self::CBOR(value, hash))
            }
            _ => Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()),
        }
    }
}

impl<T> IntoResponse for Content<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        let mut buf = BytesMut::with_capacity(128).writer();
        match self {
            Self::JSON(v, c) => match serde_json::to_writer(&mut buf, &v) {
                Ok(()) => (
                    c.unwrap_or_default(),
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static(CONTENT_TYPE_JSON),
                    )],
                    buf.into_inner().freeze(),
                )
                    .into_response(),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static(CONTENT_TYPE_TEXT),
                    )],
                    err.to_string(),
                )
                    .into_response(),
            },
            Self::CBOR(v, c) => match ciborium::into_writer(&v, &mut buf) {
                Ok(()) => (
                    c.unwrap_or_default(),
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static(CONTENT_TYPE_CBOR),
                    )],
                    buf.into_inner().freeze(),
                )
                    .into_response(),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static(CONTENT_TYPE_TEXT),
                    )],
                    err.to_string(),
                )
                    .into_response(),
            },
            Self::Text(v, c) => (
                c.unwrap_or_default(),
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(CONTENT_TYPE_TEXT),
                )],
                v,
            )
                .into_response(),
            Self::Other(v, c) => (
                c.unwrap_or(StatusCode::UNSUPPORTED_MEDIA_TYPE),
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(CONTENT_TYPE_TEXT),
                )],
                format!("Unsupported MIME type: {}", v),
            )
                .into_response(),
        }
    }
}
