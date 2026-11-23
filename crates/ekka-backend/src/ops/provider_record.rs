//! A provider write's secret is never persisted. A cold unfinished operation
//! therefore becomes unknown; matching redacted configuration proves no write.
use crate::answer::{Answer, Code};
use crate::recover::Recovery;
use crate::routes::Route;
use crate::store::{self, Record, State};

pub(super) fn existing(recovery: &Recovery, rec: &Record, route: &Route, body: &[u8]) -> Answer {
    if rec.request_digest != store::request_digest(route, body) {
        return Answer::refused(Code::OperationIdReused);
    }
    if rec.state == State::Settled {
        return super::recorded(rec, route, body);
    }
    let Some(_taken) = recovery.take(&rec.request_id) else {
        return Answer::running(&rec.request_id);
    };
    let store = recovery.store();
    // Re-read under the same in-process exclusion held by the original call.
    // The original may have settled between the first read and taking it.
    let Ok(Some(current)) = store.get(&rec.request_id) else {
        return Answer::running(&rec.request_id);
    };
    if current.state == State::Settled {
        return super::recorded(&current, route, body);
    }
    let answer = Answer::unknown();
    if store.settle(&rec.request_id, &answer).is_err() {
        return Answer::running(&rec.request_id);
    }
    answer
}
