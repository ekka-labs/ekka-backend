//! The contract's routes: exactly the operations `operations.json` names, by
//! method and path. A request matching none is `UNKNOWN_OPERATION`; a name in
//! a path that is not a plain name is `REQUEST_INVALID`.

/// The operations of `ekka.backend.v1`, in the contract's words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Create,
    Delete,
    Stop,
    Start,
    Status,
    PolicyGet,
    PolicySet,
    ProviderDetach,
    /// Reserved in v1: always refused `NOT_AVAILABLE`.
    ProviderConnect,
}

impl Operation {
    /// A change to the desk: everything but the two reads. Only a change
    /// answers `running` when it outlasts the deadline.
    #[must_use]
    pub fn mutates(self) -> bool {
        !matches!(self, Self::Status | Self::PolicyGet)
    }

    /// The operation a contract name names, as [`Operation::name`] writes it.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::Create,
            Self::Delete,
            Self::Stop,
            Self::Start,
            Self::Status,
            Self::PolicyGet,
            Self::PolicySet,
            Self::ProviderDetach,
            Self::ProviderConnect,
        ]
        .into_iter()
        .find(|o| o.name() == name)
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Delete => "delete",
            Self::Stop => "stop",
            Self::Start => "start",
            Self::Status => "status",
            Self::PolicyGet => "policy_get",
            Self::PolicySet => "policy_set",
            Self::ProviderDetach => "provider_detach",
            Self::ProviderConnect => "provider_connect",
        }
    }
}

/// A request the adapter understood: which operation, on which desk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub operation: Operation,
    pub desk: Option<String>,
    pub provider: Option<String>,
}

/// Why a request names no operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Miss {
    /// No route of the contract has this method and path.
    Unknown,
    /// The route exists, but a desk or provider in it is not a plain name.
    BadName,
}

/// `^[a-z0-9][a-z0-9._-]{0,62}$`: the contract's `name`.
#[must_use]
pub fn plain_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(c))
}

/// The route `method path` names, or why it names none. A query string is
/// part of no route.
///
/// # Errors
/// [`Miss::Unknown`] for a request outside the contract; [`Miss::BadName`]
/// for a desk or provider that is not a plain name.
pub fn route(method: &str, path: &str) -> Result<Route, Miss> {
    let parts: Vec<&str> = path.split('/').collect();
    let named = |op: Operation, desk: &str, provider: Option<&str>| {
        if !plain_name(desk) || provider.is_some_and(|p| !plain_name(p)) {
            return Err(Miss::BadName);
        }
        Ok(Route {
            operation: op,
            desk: Some(desk.to_string()),
            provider: provider.map(str::to_string),
        })
    };
    match (method, parts.as_slice()) {
        ("POST", ["", "v1", "desks"]) => Ok(Route {
            operation: Operation::Create,
            desk: None,
            provider: None,
        }),
        ("POST", ["", "v1", "providers"]) => Ok(Route {
            operation: Operation::ProviderConnect,
            desk: None,
            provider: None,
        }),
        ("DELETE", ["", "v1", "desks", d]) => named(Operation::Delete, d, None),
        ("GET", ["", "v1", "desks", d]) => named(Operation::Status, d, None),
        ("POST", ["", "v1", "desks", d, "stop"]) => named(Operation::Stop, d, None),
        ("POST", ["", "v1", "desks", d, "start"]) => named(Operation::Start, d, None),
        ("GET", ["", "v1", "desks", d, "policy"]) => named(Operation::PolicyGet, d, None),
        ("PUT", ["", "v1", "desks", d, "policy"]) => named(Operation::PolicySet, d, None),
        ("DELETE", ["", "v1", "desks", d, "providers", p]) => {
            named(Operation::ProviderDetach, d, Some(p))
        }
        _ => Err(Miss::Unknown),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "routes_tests.rs"]
mod tests;
