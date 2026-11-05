use super::{line, REDACTED};

#[test]
fn a_network_line_keeps_its_host_port_path_and_program() {
    let l = "OCSF NET: ALLOWED /usr/bin/git dst_host=github.com dst_port=443 -> github.com:443";
    assert_eq!(line(l), l);
    let l = "OCSF HTTP: ALLOWED /usr/bin/node GET https://registry.npmjs.org/express";
    assert_eq!(line(l), l);
}

#[test]
fn credentials_in_a_line_are_redacted() {
    for (input, gone) in [
        ("GET https://user:pa55@host.example/a", "pa55"),
        ("GET https://host.example/a?access_token=t0k3n&x=1", "t0k3n"),
        ("path=/a?sig=abcdef", "abcdef"),
        ("Authorization: Bearer eyJhbGciOi.payload.sig", "payload"),
        ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("password=hunter2", "hunter2"),
        ("api_key:AbC123", "AbC123"),
        ("Cookie: session=xyz", "xyz"),
        ("token ghp_aaaaaaaaaaaaaaaaaaaaaaaa", "ghp_aaaa"),
        ("leaked ghp_aaaaaaaaaaaaaaaaaaaaaaaa here", "ghp_aaaa"),
        ("aws AKIAABCDEFGHIJKLMNOP", "AKIAABCD"),
        (
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
            "eyJzdWIi",
        ),
    ] {
        let out = line(input);
        assert!(!out.contains(gone), "{input} -> {out}");
        assert!(out.contains(REDACTED), "{input} -> {out}");
    }
}

/// A line stays one line: a control character becomes a space.
#[test]
fn a_control_character_never_reaches_the_answer() {
    let out = line("OCSF NET: a\nb\r\u{1b}[31mc\u{0}");
    assert!(!out.chars().any(char::is_control), "{out:?}");
}
