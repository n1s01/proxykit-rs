use std::{borrow::Cow, time::Duration};

use proxykit::{
    gateway::{self, Format, Params, NOVA},
    Dialer, DialOptions, ErrorKind, Options, ParseOptions, Protocol, Spec,
};

fn spec(username: &str) -> Spec {
    Spec::new(Protocol::Http, "gw.example", 6969).with_auth(username, "secret")
}

fn fmt(country: &'static str, session: &'static str, ttl: &'static str) -> Format {
    Format { country: Cow::Borrowed(country), session: Cow::Borrowed(session), ttl: Cow::Borrowed(ttl), ..Format::default() }
}

fn params(country: &str, session: &str, ttl: Duration) -> Params {
    Params { country: country.into(), session: session.into(), ttl }
}

const MIN: Duration = Duration::from_secs(60);

#[test]
fn split() {
    let ssid = fmt("country", "ssid", "");
    let custom = Format { separator: "_".into(), session: "sid".into(), ttl: "life".into(), ttl_unit: Duration::from_secs(1), ..Format::default() };
    let cases = [
        (&NOVA, "acct1-country-RU-session-ab12cd34ef-time-1440", "acct1", params("RU", "ab12cd34ef", MIN * 1440)),
        (&NOVA, "acct1-country-RU", "acct1", params("RU", "", Duration::ZERO)),
        (&NOVA, "acct1", "acct1", Params::default()),
        (&ssid, "name_x-country-SI-ssid-G4h30cvPLL", "name_x", params("SI", "G4h30cvPLL", Duration::ZERO)),
        (&ssid, "acct1-country-SI-session-zz", "acct1-session-zz", params("SI", "", Duration::ZERO)),
        (&NOVA, "my-acct-city-moscow-country-RU-session-s1", "my-acct-city-moscow", params("RU", "s1", Duration::ZERO)),
        (&NOVA, "country-country-RU", "country", params("RU", "", Duration::ZERO)),
        (&NOVA, "acct1-session-time-time-5", "acct1", params("", "time", MIN * 5)),
        (&custom, "acct-1_sid_q7_life_90", "acct-1", params("", "q7", Duration::from_secs(90))),
    ];
    for (format, input, base_user, want) in cases {
        let (base, got) = format.split(&spec(input)).unwrap();
        assert_eq!(got, want, "{input}");
        assert_eq!(base, spec(base_user), "{input}");
        let again = format.apply(&base, &got).unwrap();
        assert_eq!(format.split(&again).unwrap().1, got, "round trip {input}");
    }
}

#[test]
fn apply_replaces_tags() {
    let sticky = spec("acct1-country-RU-session-old-time-1440");
    let cases = [
        (params("DE", "", Duration::ZERO), "acct1-country-DE"),
        (params("RU", "new", MIN * 30), "acct1-country-RU-session-new-time-30"),
        (params("", "new", Duration::ZERO), "acct1-session-new"),
        (Params::default(), "acct1"),
    ];
    for (p, want) in cases {
        assert_eq!(NOVA.apply(&sticky, &p).unwrap(), spec(want));
    }
    let got = NOVA.apply(&spec("my-acct-city-moscow-country-RU"), &params("DE", "s1", Duration::ZERO)).unwrap();
    assert_eq!(got.username, "my-acct-city-moscow-country-DE-session-s1");
}

#[test]
fn in_password() {
    let format = Format { separator: "_".into(), country: "country".into(), session: "session".into(), in_password: true, ..Format::default() };
    let input = Spec::new(Protocol::Socks5, "gw.example", 1080).with_auth("acct", "pw_country_us_session_s1");
    let (base, p) = format.split(&input).unwrap();
    assert_eq!((base.username.as_str(), base.password.as_str()), ("acct", "pw"));
    assert_eq!(p, params("us", "s1", Duration::ZERO));
    let out = format.apply(&base, &params("fr", "", Duration::ZERO)).unwrap();
    assert_eq!((out.username.as_str(), out.password.as_str()), ("acct", "pw_country_fr"));
}

#[test]
fn invalid() {
    let long = Spec::new(Protocol::Socks5, "gw.example", 1080).with_auth("a".repeat(250), "secret");
    let results: Vec<(&str, proxykit::Result<()>)> = vec![
        ("repeated tag", NOVA.split(&spec("a-country-RU-country-DE")).map(drop)),
        ("tag without value", NOVA.split(&spec("a-country")).map(drop)),
        ("empty value", NOVA.split(&spec("a-country--session-s1")).map(drop)),
        ("non-numeric ttl", NOVA.split(&spec("a-session-s1-time-1h")).map(drop)),
        ("zero ttl", NOVA.split(&spec("a-session-s1-time-0")).map(drop)),
        ("ttl overflow", NOVA.split(&spec("a-session-s1-time-9223372036854775807")).map(drop)),
        ("apply over malformed", NOVA.apply(&spec("a-country"), &params("RU", "", Duration::ZERO)).map(drop)),
        ("ttl without session", NOVA.apply(&spec("a"), &params("", "", Duration::from_secs(3600))).map(drop)),
        ("ttl not multiple", NOVA.apply(&spec("a"), &params("", "s1", Duration::from_secs(90))).map(drop)),
        ("value with separator", NOVA.apply(&spec("a"), &params("", "s-1", Duration::ZERO)).map(drop)),
        ("value with space", NOVA.apply(&spec("a"), &params("R U", "", Duration::ZERO)).map(drop)),
        ("parameter without tag", fmt("country", "", "").apply(&spec("a"), &params("", "s1", Duration::ZERO)).map(drop)),
        (
            "no credentials",
            NOVA.apply(&Spec::new(Protocol::Http, "gw.example", 6969), &params("RU", "", Duration::ZERO)).map(drop),
        ),
        ("socks5 username limit", NOVA.apply(&long, &params("RU", "", Duration::ZERO)).map(drop)),
        ("format without tags", Format::default().split(&spec("a")).map(drop)),
        ("duplicate format tags", fmt("x", "x", "").split(&spec("a")).map(drop)),
        ("format tag with separator", fmt("", "session-id", "").split(&spec("a")).map(drop)),
    ];
    for (name, result) in results {
        let e = result.expect_err(name);
        assert_eq!(e.kind(), ErrorKind::Invalid, "{name}: {e}");
        assert!(!e.to_string().contains("secret"), "{name} leaks credentials");
    }
}

#[test]
fn new_session() {
    let (a, b) = (gateway::new_session(), gateway::new_session());
    assert_ne!(a, b);
    for s in [a, b] {
        assert_eq!(s.len(), 10);
        assert!(s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()), "{s}");
    }
}

#[test]
fn parsed_line_to_dialer() {
    for line in [
        "gw.example:6969:acct1-country-RU-session-ab12cd34ef-time-1440:secret",
        "name_x-country-SI-session-G4h30cvPLL:secret:gw.example:17522",
    ] {
        let parsed = proxykit::parse_with(line, &ParseOptions { default_protocol: Protocol::Http, ..Default::default() }).unwrap();
        let (_, mut p) = NOVA.split(&parsed).unwrap();
        assert!(p.sticky());
        p.session = gateway::new_session();
        let rotated = NOVA.apply(&parsed, &p).unwrap();
        let dialer = Dialer::new(rotated, DialOptions::default()).unwrap();
        assert!(dialer.spec().username.contains(&format!("-session-{}", p.session)));
    }
}

#[tokio::test]
async fn new_builds_dialer() {
    let opts = Options { parse: ParseOptions { default_protocol: Protocol::Socks5, ..Default::default() }, ..Default::default() };
    let d = NOVA.dialer("gw.example:6969:acct1:secret", params("RU", "", MIN * 1440), opts.clone()).await.unwrap();
    let got = d.spec();
    let (_, p) = NOVA.split(got).unwrap();
    assert_eq!(got.protocol, Protocol::Socks5);
    assert_eq!((p.country.as_str(), p.session.len(), p.ttl), ("RU", 10, MIN * 1440));
    assert_eq!(got.username, format!("acct1-country-RU-session-{}-time-1440", p.session));

    let d = NOVA.dialer("http://acct1:secret@gw.example:6969", params("DE", "", Duration::ZERO), Options::default()).await.unwrap();
    assert_eq!(d.spec().url(), "http://acct1-country-DE:secret@gw.example:6969");

    let e = NOVA.dialer("gw.example:6969:acct1:secret", params("", "s-1", Duration::ZERO), opts).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Invalid);
}
