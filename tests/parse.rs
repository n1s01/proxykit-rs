use proxykit::{parse, parse_json, parse_lines, parse_with, ErrorKind, Layout, ParseOptions, Protocol, Spec};

fn spec(protocol: Protocol, host: &str, port: u16, user: &str, pass: &str) -> Spec {
    Spec::new(protocol, host, port).with_auth(user, pass)
}

fn opts(layout: &str, default_protocol: Protocol) -> ParseOptions {
    ParseOptions { layout: layout.into(), default_protocol }
}

#[test]
fn parse_formats_and_round_trip() {
    use Protocol::*;
    let cases = [
        ("host.test:8080", spec(Auto, "host.test", 8080, "", "")),
        ("user:pass:HOST.test@3128", spec(Auto, "host.test", 3128, "user", "pass")),
        ("host.test:3128:user:pass", spec(Auto, "host.test", 3128, "user", "pass")),
        ("user:pass:host.test:3128", spec(Auto, "host.test", 3128, "user", "pass")),
        ("HTTP://user:p%40ss%3A%2F%25@host.test:3128/", spec(Http, "host.test", 3128, "user", "p@ss:/%")),
        ("socks5h://[2001:db8::1]:1080", spec(Socks5, "2001:db8::1", 1080, "", "")),
        ("[::1]:1080", spec(Auto, "::1", 1080, "", "")),
        ("https://u:p@[::1]:8443", spec(Https, "::1", 8443, "u", "p")),
    ];
    for (raw, want) in cases {
        let got = parse(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
        assert_eq!(got, want, "{raw}");
        assert_eq!(parse(&got.url()).unwrap(), got, "URL round trip of {raw}");
    }
}

#[test]
fn parse_rejects_invalid_and_ambiguous() {
    for raw in [
        "",
        "null",
        "http://host:0",
        "http://host:65536",
        "http://:80",
        "http://host:-1",
        "ftp://host:80",
        "socks4://host:80",
        "http://host",
        "http://host:80/path",
        "http://host:80?x=1",
        "http://host:80#x",
        "http://u:se%ZZcret@host:80",
        "http://ho st:80",
        "http://host:80\r\nX: y",
        "http://u%3As:p@host:80",
        "socks5://:p@host:1080",
        "socks5://u:@host:1080",
        "2001:db8::1:80",
        "http://[invalid]:80",
        "[invalid]:80",
    ] {
        assert!(parse(raw).is_err(), "accepted {raw:?}");
    }
    assert_eq!(parse("host:123:user:456").unwrap_err().kind(), ErrorKind::Ambiguous);
    let s = parse_with("host:123:user:456", &ParseOptions { default_protocol: Protocol::Http, layout: Layout::HOST_PORT_USER_PASS })
        .unwrap();
    assert_eq!((s.host.as_str(), s.port, s.password.as_str(), s.protocol), ("host", 123, "456", Protocol::Http));
    let s = parse_with("host:123:user:456", &ParseOptions { layout: Layout::USER_PASS_HOST_PORT, ..Default::default() })
        .unwrap();
    assert_eq!((s.host.as_str(), s.port, s.password.as_str()), ("user", 456, "123"));
    assert!(parse(&format!("socks5://{}:p@host:80", "u".repeat(256))).is_err());
}

#[test]
fn json_forms() {
    let want = spec(Protocol::Socks5, "host", 1080, "u", "p");
    for raw in [
        r#""socks5://u:p@host:1080""#,
        r#"["socks5","host",1080,true,"u","p"]"#,
        r#"["socks5h","host","1080",null,"u","p"]"#,
        r#"{"protocol":"socks5","host":"host","port":1080,"username":"u","password":"p"}"#,
    ] {
        assert_eq!(parse_json(raw, &ParseOptions::default()).unwrap(), want, "{raw}");
    }
    for raw in [
        "null",
        "[]",
        r#"["http","host",1.5]"#,
        r#"["http","host",-1]"#,
        r#"["socks5","host",1080,false]"#,
        r#"["http","host",80,true,42]"#,
        r#"{"host":"host","port":80,"unknown":true}"#,
        r#"{"host":"host","port":80} {}"#,
        r#"["http","host",80,true,"u","p",7]"#,
    ] {
        assert!(parse_json(raw, &ParseOptions::default()).is_err(), "accepted {raw}");
    }
    let s = parse_json(r#"{"host":"host","port":80}"#, &ParseOptions { default_protocol: Protocol::Https, ..Default::default() })
        .unwrap();
    assert_eq!(s.protocol, Protocol::Https);
}

#[test]
fn no_secrets_in_formatting_or_errors() {
    let s = spec(Protocol::Http, "host", 80, "private-user", "private-password");
    for text in [format!("{s}"), format!("{s:?}"), format!("{s:#?}")] {
        assert!(!text.contains("private"), "{text}");
    }
    let e = parse("http://private-user:private-password@host:bad").unwrap_err();
    assert!(!e.to_string().contains("private"));
    let (specs, errs) = parse_lines("# comment\r\nhost:80\r\n\nbad\nhost:80", &ParseOptions::default());
    assert_eq!(specs.len(), 2);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].line, 4);
}

#[test]
fn serde_spec_round_trip() {
    let s = spec(Protocol::Socks5, "host", 1080, "u", "p");
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, r#"{"protocol":"socks5","host":"host","port":1080,"username":"u","password":"p"}"#);
    assert_eq!(serde_json::from_str::<Spec>(&json).unwrap(), s);
    assert_eq!("socks5://u:p@host:1080".parse::<Spec>().unwrap(), s);
}

fn permutations(fields: &[&'static str]) -> Vec<Vec<&'static str>> {
    if fields.is_empty() {
        return vec![vec![]];
    }
    let mut out = Vec::new();
    for i in 0..fields.len() {
        let mut rest = fields.to_vec();
        let f = rest.remove(i);
        for mut tail in permutations(&rest) {
            tail.insert(0, f);
            out.push(tail);
        }
    }
    out
}

fn allowed_layout_mask(order: &[&str], mask: usize) -> bool {
    if mask == 0 {
        return true;
    }
    let endpoint = |f: &str| f == "host" || f == "port";
    for i in 0..order.len() - 1 {
        if mask != 1 << i {
            continue;
        }
        if endpoint(order[i]) && endpoint(order[i + 1]) {
            return true;
        }
        return i == 1 && endpoint(order[0]) == endpoint(order[1]) && endpoint(order[2]) == endpoint(order[3]);
    }
    false
}

fn layout_input(order: &[&str], mask: usize, value: impl Fn(&str) -> String) -> (String, String) {
    let (mut layout, mut raw) = (String::new(), String::new());
    for (i, field) in order.iter().enumerate() {
        if i > 0 {
            let sep = if mask & (1 << (i - 1)) != 0 { '@' } else { ':' };
            layout.push(sep);
            raw.push(sep);
        }
        layout.push_str(field);
        raw.push_str(&value(field));
    }
    (layout, raw)
}

#[test]
fn explicit_layouts_all_orders_and_separators() {
    let orders = permutations(&["host", "port", "login", "pass"]);
    assert_eq!(orders.len(), 24);
    let mut checked = 0;
    for host in ["Proxy.Example", "192.0.2.1", "[2001:db8::1]"] {
        for prefix in ["", "http://", "https://", "socks5://", "socks5h://", "auto://"] {
            for order in &orders {
                for mask in 0..8 {
                    if !allowed_layout_mask(order, mask) {
                        continue;
                    }
                    let (layout, raw) = layout_input(order, mask, |f| {
                        match f {
                            "host" => host,
                            "port" => "1080",
                            "login" => "123",
                            _ => "456",
                        }
                        .to_string()
                    });
                    let want_protocol = match prefix {
                        "" | "auto://" => Protocol::Http,
                        p => p.trim_end_matches("://").parse().unwrap(),
                    };
                    let want = spec(
                        want_protocol,
                        &host.trim_matches(['[', ']']).to_ascii_lowercase(),
                        1080,
                        "123",
                        "456",
                    );
                    let got = parse_with(&format!("{prefix}{raw}"), &opts(&layout, Protocol::Http))
                        .unwrap_or_else(|e| panic!("{prefix}{raw} with {layout}: {e}"));
                    assert_eq!(got, want, "{layout}");
                    assert_eq!(parse(&got.url()).unwrap(), want);
                    checked += 1;
                }
            }
        }
    }
    // (24 colon + 12 endpoint-@ + 8 pair-@) layouts × 3 hosts × 6 prefixes.
    assert_eq!(checked, 44 * 3 * 6);
}

#[test]
fn at_cannot_separate_credential_fields() {
    for order in permutations(&["host", "port", "login", "pass"]) {
        for mask in 1..8 {
            if allowed_layout_mask(&order, mask) {
                continue;
            }
            let (layout, raw) = layout_input(&order, mask, |f| {
                match f {
                    "host" => "host.test",
                    "port" => "8080",
                    "login" => "u",
                    _ => "p",
                }
                .to_string()
            });
            let e = parse_with(&raw, &opts(&layout, Protocol::Auto)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Invalid, "{layout}");
        }
    }
    for raw in ["u@p:host.test:8080", "host.test:8080:u@p", "host.test@8080@u@p", "u:p@host.test@8080"] {
        assert_eq!(parse(raw).unwrap_err().kind(), ErrorKind::Invalid, "{raw}");
    }
}

#[test]
fn ip_layout_alias() {
    let s = parse_with("192.0.2.1@1080:secret:alice", &opts("ip@port:pass:login", Protocol::Auto)).unwrap();
    assert_eq!((s.host.as_str(), s.port, s.username.as_str(), s.password.as_str()), ("192.0.2.1", 1080, "alice", "secret"));
}

#[test]
fn automatic_layouts_and_reverse_endpoint() {
    for raw in [
        "proxy.example:1080:login:pass",
        "login:pass:proxy.example:1080",
        "proxy.example@1080:login:pass",
        "login:pass:proxy.example@1080",
        "1080@proxy.example:login:pass",
        "proxy.example:login!:1080:pass!",
        "http://proxy.example@1080:login:pass",
    ] {
        let s = parse(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
        let (user, pass) = if raw.contains('!') { ("login!", "pass!") } else { ("login", "pass") };
        assert_eq!((s.host.as_str(), s.port, s.username.as_str(), s.password.as_str()), ("proxy.example", 1080, user, pass), "{raw}");
    }
    for raw in ["proxy.example:1080", "1080:proxy.example", "proxy.example@1080", "1080@proxy.example", "1080@[::1]", "http://1080:proxy.example"]
    {
        let s = parse(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
        assert!(s.port == 1080 && !s.has_auth(), "{raw}");
    }
    for raw in ["123:456", "login:proxy.example:1080:pass", "host:123:user:456"] {
        assert_eq!(parse(raw).unwrap_err().kind(), ErrorKind::Ambiguous, "{raw}");
    }
}

#[test]
fn at_divides_credentials_from_endpoint() {
    for raw in ["login:pass@proxy.example:1080", "proxy.example:1080@login:pass", "http://login:pass@proxy.example:1080"] {
        let s = parse(raw).unwrap();
        assert_eq!((s.host.as_str(), s.port, s.username.as_str(), s.password.as_str()), ("proxy.example", 1080, "login", "pass"));
    }
    let s = parse("login:8080@host.test:3071").unwrap();
    assert_eq!((s.host.as_str(), s.port, s.username.as_str(), s.password.as_str()), ("host.test", 3071, "login", "8080"));
    let s = parse("192.0.2.1:8080@login:pass").unwrap();
    assert_eq!((s.host.as_str(), s.port, s.username.as_str(), s.password.as_str()), ("192.0.2.1", 8080, "login", "pass"));
    let s = parse_with("secret:alice@[::1]:1080", &opts("pass:login@host:port", Protocol::Auto)).unwrap();
    assert_eq!((s.host.as_str(), s.port, s.username.as_str(), s.password.as_str()), ("::1", 1080, "alice", "secret"));
    let (specs, failures) =
        parse_lines("j3q9jBNN:xBYEKEAf@dc01.proxy.example:3071\n0KHdNey2:3fphh1oy@dc04.proxy.example:3071", &ParseOptions::default());
    assert_eq!(specs.len(), 2);
    assert!(failures.is_empty());
    assert_eq!(specs[1].host, "dc04.proxy.example");
    assert_eq!(specs[1].username, "0KHdNey2");
}

#[test]
fn numeric_credentials_keep_endpoint_with_at_separator() {
    for raw in ["host@80:login:90", "login:90:host@80", "http://host@80:login:90"] {
        let s = parse(raw).unwrap();
        assert_eq!((s.host.as_str(), s.port, s.username.as_str(), s.password.as_str()), ("host", 80, "login", "90"), "{raw}");
    }
    let s = parse_with("host@80:90:login", &opts("host@port:pass:login", Protocol::Auto)).unwrap();
    assert_eq!((s.username.as_str(), s.password.as_str()), ("login", "90"));
}

#[test]
fn explicit_optional_credentials_and_aliases() {
    let cases = [
        ("8080@host.test", "port@host", "", ""),
        ("host.test:8080:login", "host:port:username", "login", ""),
        ("secret:8080@host.test", "password:port@host", "", "secret"),
        ("secret:login:host.test@8080", "pass:user:host@port", "login", "secret"),
        ("host.test@8080::secret", "host@port:login:password", "", "secret"),
        ("host.test@8080:login:", "host@port:user:pass", "login", ""),
        ("host.test:8080:login:p%40ss", " HOST : PORT : LOGIN : PASSWORD ", "login", "p%40ss"),
    ];
    for (raw, layout, user, pass) in cases {
        let s = parse_with(raw, &opts(layout, Protocol::Http)).unwrap_or_else(|e| panic!("{raw}: {e}"));
        assert_eq!((s.host.as_str(), s.port, s.username.as_str(), s.password.as_str()), ("host.test", 8080, user, pass), "{raw}");
    }
}

#[test]
fn layouts_reject_invalid_inputs_without_exposing_credentials() {
    for layout in ["host", "host:login", "host:port:user:login", "host:port:pass:password", "host:port:unknown", "host:port:user:pass:extra", "host/port", "host::port"]
    {
        assert_eq!(parse_with("host.test:80", &opts(layout, Protocol::Auto)).unwrap_err().kind(), ErrorKind::Invalid, "{layout}");
    }
    for raw in [
        "host.test@80:private-login:private-password",
        "host.test:0:private-login:private-password",
        "[invalid]:80:private-login:private-password",
        "[::1]suffix:80:private-login:private-password",
        "[::1:80:private-login:private-password",
        "host.test:80:private-login:private-password:extra",
        "host.test:80:private-login:private-password\r\ninjected",
    ] {
        let e = parse_with(raw, &ParseOptions { layout: Layout::HOST_PORT_USER_PASS, ..Default::default() }).unwrap_err();
        assert!(!e.to_string().contains("private"), "{e}");
    }
    for raw in ["socks4://host.test:80:p:u", "unknown://host.test:80:p:u"] {
        assert_eq!(parse_with(raw, &opts("host:port:pass:login", Protocol::Auto)).unwrap_err().kind(), ErrorKind::Protocol);
    }
    for raw in ["http://u%3As:p@host:80", "http://u:se%ZZcret@host:80", "http://user:123@host:80/path", "socks5://:p@host:1080"] {
        assert!(parse(raw).is_err(), "failed URL was reinterpreted: {raw}");
    }
}

#[test]
fn layouts_flow_through_json_and_lines() {
    let o = opts("pass:login:port@host", Protocol::Https);
    let want = spec(Protocol::Https, "host.test", 8080, "u", "p");
    assert_eq!(parse_json(r#""p:u:8080@host.test""#, &o).unwrap(), want);
    let (specs, failures) = parse_lines("# list\np:u:8080@host.test\nbad", &o);
    assert_eq!(specs, vec![want]);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].line, 3);
}

#[test]
fn structured_endpoints_enforce_protocol_constraints() {
    assert!(Spec::new(Protocol::Auto, "host.test", 80).validate().is_ok());
    let bad = [
        Spec::new(Protocol::Http, "", 80),
        Spec::new(Protocol::Http, "host.test", 0),
        spec(Protocol::Http, "host.test", 80, "a:b", "p"),
        spec(Protocol::Socks5, "host.test", 1080, "u", ""),
        spec(Protocol::Http, "host.test", 80, "", "p\r\n"),
    ];
    for s in bad {
        assert_eq!(s.validate().unwrap_err().kind(), ErrorKind::Invalid, "{s:?}");
    }
}

/// A light deterministic fuzz: whatever parses must validate and round-trip.
#[test]
fn successful_parses_round_trip() {
    let alphabet = ['a', '1', ':', '@', '[', ']', '.', '%', '/', 'h', '8', '0', ':', 'z'];
    let mut seed = 0x2545F4914F6CDD1Du64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let seeds = ["host:80", "socks5://u:p@[::1]:1080", "host:1:user:2", "http://u:p%40x@host:80", "host:80@u:p", "80@[::1]"];
    for i in 0..20_000 {
        let mut raw: String = seeds[i % seeds.len()].to_string();
        for _ in 0..(next() % 4) {
            let pos = (next() as usize) % (raw.len() + 1);
            if raw.is_char_boundary(pos) {
                raw.insert(pos, alphabet[(next() as usize) % alphabet.len()]);
            }
        }
        if let Ok(s) = parse(&raw) {
            s.validate().unwrap();
            assert_eq!(parse(&s.url()).unwrap(), s, "{raw}");
        }
    }
}
