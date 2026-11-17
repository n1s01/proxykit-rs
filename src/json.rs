use serde_json::Value;

use crate::{
    error::{Error, Result},
    parse::{parse_with, validate_options, ParseOptions},
    spec::{parse_port, Protocol, Spec},
};

/// Accepts a JSON string, a `Spec` object or a Telethon-style tuple
/// `[protocol, host, port, rdns, username, password]`. Explicit local DNS
/// (`rdns = false`) is rejected: silently changing routing is unsafe.
/// `null` is invalid. The layout applies only to the string form.
pub fn parse_json(raw: impl AsRef<[u8]>, opts: &ParseOptions) -> Result<Spec> {
    validate_options(opts)?;
    let text = std::str::from_utf8(raw.as_ref()).map_err(|_| Error::invalid("JSON encoding"))?.trim();
    match text.as_bytes().first() {
        None => Err(Error::invalid("empty JSON")),
        Some(b'"') => {
            let s: String = serde_json::from_str(text).map_err(|_| Error::invalid("JSON string"))?;
            parse_with(&s, opts)
        }
        Some(b'{') => {
            let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text) else {
                return Err(Error::invalid("JSON object"));
            };
            let mut spec = Spec::default();
            let mut protocol = String::new();
            for (key, value) in &map {
                match key.as_str() {
                    "protocol" => protocol = json_string(value).ok_or_else(object_err)?,
                    "host" => spec.host = json_string(value).ok_or_else(object_err)?,
                    "username" => spec.username = json_string(value).ok_or_else(object_err)?,
                    "password" => spec.password = json_string(value).ok_or_else(object_err)?,
                    "port" => spec.port = json_port_number(value)?,
                    _ => return Err(object_err()),
                }
            }
            spec.protocol = with_default(Protocol::parse(&protocol)?, opts);
            spec.validated()
        }
        Some(b'[') => {
            let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(text) else {
                return Err(Error::invalid("JSON tuple length"));
            };
            if !(3..=6).contains(&parts.len()) {
                return Err(Error::invalid("JSON tuple length"));
            }
            let (Some(protocol), Some(host)) = (json_string(&parts[0]), json_string(&parts[1])) else {
                return Err(Error::invalid("tuple protocol/host must be strings"));
            };
            let port = match &parts[2] {
                Value::String(s) => parse_port(s)?,
                other => json_port_number(other).map_err(|_| Error::invalid("tuple port"))?,
            };
            if let Some(rdns) = parts.get(3) {
                if !rdns.is_null() && rdns.as_bool() != Some(true) {
                    return Err(Error::invalid("tuple requires remote DNS"));
                }
            }
            let username = match parts.get(4) {
                Some(v) => json_string(v).ok_or_else(|| Error::invalid("tuple username"))?,
                None => String::new(),
            };
            let password = match parts.get(5) {
                Some(v) => json_string(v).ok_or_else(|| Error::invalid("tuple password"))?,
                None => String::new(),
            };
            let protocol = with_default(Protocol::parse(&protocol)?, opts);
            Spec { protocol, host, port, username, password }.validated()
        }
        Some(_) => Err(Error::invalid("expected JSON string, object or tuple")),
    }
}

fn object_err() -> Error {
    Error::invalid("JSON object")
}

fn with_default(p: Protocol, opts: &ParseOptions) -> Protocol {
    if p == Protocol::Auto {
        opts.default_protocol
    } else {
        p
    }
}

/// Strings, with `null` meaning empty, as Go decodes them.
fn json_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => Some(String::new()),
        _ => None,
    }
}

/// Integral port numbers; range errors surface from validation.
fn json_port_number(v: &Value) -> Result<u16> {
    match v {
        Value::Null => Ok(0),
        Value::Number(n) => match n.as_i64() {
            Some(p) if (0..=65535).contains(&p) => Ok(p as u16),
            Some(_) => Err(Error::invalid("port must be in 1..65535")),
            None => Err(Error::invalid("port")),
        },
        _ => Err(Error::invalid("port")),
    }
}
