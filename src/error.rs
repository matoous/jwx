use std::fmt::{self, Display, Formatter};

#[derive(Debug, PartialEq)]
pub struct Error {
    /// Debug message associated with error
    pub msg: &'static str,
    pub typ: Type,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.typ, self.msg)
    }
}

impl std::error::Error for Error {}

/// Type of error encountered.
#[derive(Debug, PartialEq)]
pub enum Type {
    /// Token is invalid.
    Invalid,
    /// Token has expired.
    Expired,
    /// Not Before (nbf) is set and it's too early to use the token.
    Early,
    /// Problem with certificate.
    Certificate,
    /// Problem with key.
    Key,
    /// Could not download key set.
    Connection,
    /// Problem with JWT header.
    Header,
    /// Problem with JWT payload.
    Payload,
    /// Problem with JWT signature.
    Signature,
    /// Internal problem (Signals a serious bug or fatal error).
    Internal,
}

#[macro_export]
macro_rules! err {
    ( $typ:ident, $msg:expr ) => {{
        Error {
            msg: $msg,
            typ: Type::$typ,
        }
    }};
}
