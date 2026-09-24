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
                            || mime.suffix().is_some_and(|name| name == "cbor")
                        {
                            return Content::CBOR((), None);
                        } else if mime.subtype() == "json"
                            || mime.suffix().is_some_and(|name| name == "json")
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

/// Reads a JSON or CBOR request body, returning the decoded value, the raw body,
/// and whether it is CBOR.
#[allow(clippy::result_large_err)] // same as the `FromRequest::Rejection` type
async fn from_body<T, S>(req: Request, state: &S) -> Result<(T, Bytes, bool), Response>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    let is_cbor = match Content::from_content_type(req.headers()) {
        Content::CBOR(_, _) => true,
        Content::JSON(_, _) => false,
        _ => return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()),
    };
    let body = Bytes::from_request(req, state)
        .await
        .map_err(IntoResponse::into_response)?;
    let value = if is_cbor {
        cbor2::from_slice(&body[..]).map_err(|err| err.to_string())
    } else {
        serde_json::from_slice(&body).map_err(|err| err.to_string())
    }
    .map_err(|err| Content::Text::<()>(err, Some(StatusCode::BAD_REQUEST)).into_response())?;
    Ok((value, body, is_cbor))
}

impl<S, T> FromRequest<S> for Content<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (value, _, is_cbor) = from_body(req, state).await?;
        Ok(if is_cbor {
            Self::CBOR(value, None)
        } else {
            Self::JSON(value, None)
        })
    }
}

impl<S, T> FromRequest<S> for ContentWithSHA3<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (value, body, is_cbor) = from_body(req, state).await?;
        let hash = sha3_256(&body);
        Ok(if is_cbor {
            Self::CBOR(value, hash)
        } else {
            Self::JSON(value, hash)
        })
    }
}

fn encode<T: Serialize>(value: &T, is_cbor: bool) -> Result<Bytes, String> {
    let mut buf = BytesMut::with_capacity(128).writer();
    if is_cbor {
        cbor2::to_writer(value, &mut buf).map_err(|err| err.to_string())?;
    } else {
        serde_json::to_writer(&mut buf, value).map_err(|err| err.to_string())?;
    }
    Ok(buf.into_inner().freeze())
}

impl<T> IntoResponse for Content<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        let (status, content_type, body) = match self {
            Self::JSON(v, c) => (c, CONTENT_TYPE_JSON, encode(&v, false)),
            Self::CBOR(v, c) => (c, CONTENT_TYPE_CBOR, encode(&v, true)),
            Self::Text(v, c) => (c, CONTENT_TYPE_TEXT, Ok(Bytes::from(v))),
            Self::Other(v, c) => (
                Some(c.unwrap_or(StatusCode::UNSUPPORTED_MEDIA_TYPE)),
                CONTENT_TYPE_TEXT,
                Ok(Bytes::from(format!("Unsupported MIME type: {}", v))),
            ),
        };

        match body {
            Ok(body) => (
                status.unwrap_or_default(),
                [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
                body,
            )
                .into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(CONTENT_TYPE_TEXT),
                )],
                err,
            )
                .into_response(),
        }
    }
}
