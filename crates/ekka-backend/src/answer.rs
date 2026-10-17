//! The one closed answer shape of `ekka.backend.v1` (`backend-v1.schema.json`
//! `$defs.result`), and the HTTP status each outcome is sent with
//! (`operations.json` `outcome_table`). Every response the adapter sends is
//! one of these; a backend's own error text is never forwarded.

use serde::{Deserialize, Serialize};

// The contract's whole vocabulary of outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    /// This call did the work.
    First,
    /// This operation was already answered; the recorded answer, with nothing
    /// sent to the backend again.
    /// A recorded answer, delivered again.
    #[cfg_attr(not(test), allow(dead_code))]
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ready,
    Refused,
    Unknown,
    Running,
}

/// Why an answer is refused, in the contract's words: the contract's whole
/// list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Code {
    TokenMissing,
    TokenInvalid,
    TokenExpired,
    TokenReplayed,
    TokenScope,
    CredentialMissing,
    RequestInvalid,
    UnknownOperation,
    NotAvailable,
    ConstraintsInvalid,
    ConstraintImageDigests,
    ConstraintPolicyDigests,
    ConstraintAllowedHosts,
    ConstraintProviders,
    ConstraintProviderConfigDigests,
    ConstraintEnvironmentKeys,
    ConstraintPolicyBaseline,
    ConstraintCredentialEndpoint,
    FieldNotAllowed,
    OperationIdReused,
    DeskNotFound,
    DeskExists,
    DeskProviderRequired,
    DeskBusy,
    VersionConflict,
    BackendUnavailable,
    BackendRefused,
    /// A create that never reached the desk: a settle marker and the
    /// gateway's own read-back after its restart prove nothing was created.
    NotApplied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub delivery: Delivery,
    pub outcome: Outcome,
    /// Absent only on `running`, by the outcome table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desk_ready: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Code>,
    /// On `running` only: the operation's request id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// What the desk is now, as the adapter read it back.
    #[serde(flatten)]
    pub desk: DeskFacts,
}

/// The facts about a desk an answer may carry: the backend's id for it, its
/// configuration version, its policy digest, its providers' digest and its
/// providers. Each is sent only when read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeskFacts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub providers_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub providers: Option<Vec<String>>,
}

impl Answer {
    /// Done, and the desk is as asked: `ready`, with what was read back.
    #[must_use]
    pub fn ready(desk: DeskFacts) -> Self {
        Self {
            delivery: Delivery::First,
            outcome: Outcome::Ready,
            desk_ready: Some(true),
            code: None,
            operation_id: None,
            desk,
        }
    }

    /// The change was admitted and its result cannot be told (the work
    /// failed part way): nothing says the desk is as asked.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            delivery: Delivery::First,
            outcome: Outcome::Unknown,
            desk_ready: Some(false),
            code: None,
            operation_id: None,
            desk: DeskFacts::default(),
        }
    }

    /// The change reached the deadline after it was admitted and goes on:
    /// only `{delivery: first, outcome: running, operation_id}`, HTTP 202.
    #[must_use]
    pub fn running(request_id: &str) -> Self {
        Self {
            delivery: Delivery::First,
            outcome: Outcome::Running,
            desk_ready: None,
            code: None,
            operation_id: Some(request_id.to_string()),
            desk: DeskFacts::default(),
        }
    }

    /// A refusal: nothing changed, and `code` says why.
    #[must_use]
    pub fn refused(code: Code) -> Self {
        Self {
            delivery: Delivery::First,
            outcome: Outcome::Refused,
            desk_ready: Some(false),
            code: Some(code),
            operation_id: None,
            desk: DeskFacts::default(),
        }
    }

    /// The HTTP status the outcome table gives this answer: 202 for
    /// `running`, 200 for every other outcome.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self.outcome {
            Outcome::Running => 202,
            Outcome::Ready | Outcome::Refused | Outcome::Unknown => 200,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde_json::Value;

    use super::{Answer, Delivery, Outcome};

    /// Each outcome's HTTP status and `desk_ready` are the contract's outcome
    /// table (operations.json): 202 only for `running`, which carries no
    /// `desk_ready`.
    #[test]
    fn the_outcome_table_is_the_contracts() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/contracts/backend/operations.json"
        );
        let ops: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let table = ops["outcome_table"].as_array().unwrap();
        assert_eq!(table.len(), 4);
        for (o, ready) in [
            (Outcome::Ready, Some(true)),
            (Outcome::Refused, Some(false)),
            (Outcome::Unknown, Some(false)),
            (Outcome::Running, None),
        ] {
            let a = Answer {
                delivery: Delivery::First,
                outcome: o,
                desk_ready: ready,
                code: None,
                operation_id: None,
                desk: super::DeskFacts::default(),
            };
            let name = serde_json::to_value(o).unwrap();
            let row = table.iter().find(|r| r["outcome"] == name).unwrap();
            assert_eq!(
                u64::from(a.http_status()),
                row["http_status"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(
                row.get("desk_ready").and_then(Value::as_bool),
                ready,
                "{name}"
            );
        }
        assert_eq!(
            serde_json::to_value(Delivery::Duplicate).unwrap(),
            "duplicate"
        );
    }
}
