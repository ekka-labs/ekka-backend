use serde_json::Value;

use super::{route, Miss, Operation};

fn operations() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/contracts/backend/operations.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// THE ROUTES ARE THE CONTRACT'S. Every operation in the vendored
/// operations.json is reached by its method and path, under its own name,
/// and nothing else is: the adapter serves no route the contract lacks.
#[test]
fn every_route_is_the_contracts_and_only_those() {
    let ops = operations();
    let list = ops["operations"].as_array().unwrap();
    assert_eq!(ops["contract"], "ekka.backend");
    assert_eq!(ops["contract_version"], 1);
    for o in list {
        let path = o["path"]
            .as_str()
            .unwrap()
            .replace("{name}", "shop")
            .replace("{provider}", "github");
        let method = o["method"].as_str().unwrap();
        let r = route(method, &path).unwrap();
        assert_eq!(r.operation.name(), o["operation"], "{method} {path}");
        let reserved = o["reserved"].as_bool().unwrap();
        assert_eq!(
            reserved,
            r.operation == Operation::ProviderConnect,
            "{method} {path}"
        );
    }
    assert_eq!(list.len(), 9, "nine operations in v1");
}

#[test]
fn a_request_outside_the_contract_is_unknown() {
    for (m, p) in [
        ("GET", "/v1/desks"),
        ("PATCH", "/v1/desks/shop"),
        ("POST", "/v1/desks/shop/restart"),
        ("GET", "/v2/desks/shop"),
        ("GET", "/v1/desks/shop/"),
        ("DELETE", "/v1/desks/shop/providers"),
        ("GET", "/"),
    ] {
        assert_eq!(route(m, p), Err(Miss::Unknown), "{m} {p}");
    }
}

/// A name in a path is the contract's plain name: never a path, an encoded
/// separator, or anything a shell or a later join could read twice.
#[test]
fn a_name_that_is_not_plain_is_refused() {
    for p in [
        "/v1/desks/Shop",
        "/v1/desks/..",
        "/v1/desks/-x",
        "/v1/desks/a%2Fb",
        "/v1/desks/shop/providers/Git%20Hub",
    ] {
        let m = if p.contains("providers") {
            "DELETE"
        } else {
            "GET"
        };
        assert_eq!(route(m, p), Err(Miss::BadName), "{p}");
    }
    let long = format!("/v1/desks/{}", "a".repeat(64));
    assert_eq!(route("GET", &long), Err(Miss::BadName));
    assert!(route("GET", &format!("/v1/desks/{}", "a".repeat(63))).is_ok());
}
