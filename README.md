# proxykit (Rust)

Rust-порт Go-библиотеки [`github.com/n1s01/proxykit`](https://github.com/n1s01/proxykit):
разбор прокси, определение протокола, TCP-туннели, HTTP-клиент, проверки доступности
и скорости, обход VPN/WARP и локальный relay для браузера. HTTP CONNECT, HTTPS CONNECT, SOCKS5.
Async на tokio, TLS на rustls (ring), HTTP на hyper. Без OpenSSL.

```text
строка → proxykit::new → Dialer → TCP-туннель / HTTP-клиент / browser relay
             │             └── check → результат + типизированная ошибка
             └── parse → detect (только при неизвестном протоколе)
```

## Подключение

```toml
[dependencies]
proxykit = { git = "https://github.com/n1s01/proxykit-rs" }
# или локально: proxykit = { path = "../proxykit-rs" }
tokio = { version = "1", features = ["full"] }
```

## Быстрый старт

```rust
use proxykit::{CheckOptions, Options};

#[tokio::main]
async fn main() -> proxykit::Result<()> {
    let proxy = proxykit::new("user:pass:proxy.example@1080", Options {
        target: "web.telegram.org:443".into(),
        ..Default::default()
    }).await?;

    let result = proxy.check(CheckOptions::url("https://web.telegram.org/")).await?;
    println!("{}: tunnel={:?}, total={:?}", proxy.spec(), result.tunnel_latency, result.duration);
    Ok(())
}
```

## Соответствие Go → Rust

| Go | Rust |
|---|---|
| `proxykit.New(ctx, s, Options{...})` | `proxykit::new(s, Options { .. }).await` |
| `proxykit.Parse`, `ParseWithOptions` | `proxykit::parse`, `parse_with(s, &ParseOptions)` |
| `ParseJSON`, `ParseLines` | `parse_json`, `parse_lines` |
| `NewDialer(spec, DialOptions{})` | `Dialer::new(spec, DialOptions::default())` |
| `d.DialContext(ctx, "tcp", target)` | `d.connect(target).await` → `Tunnel` (`AsyncRead + AsyncWrite`) |
| `d.Transport()` + `http.Client` | `d.http_client()` (hyper, HTTP/1.1 + HTTP/2) |
| `d.Check`, `Check`, `CheckAll` | `d.check`, `check`, `check_all` / `check_stream` |
| `Detect`, `Resolve` | `detect`, `resolve` |
| `SpeedTest`, `Inspect` | `speed_test`, `inspect` (+ методы `Dialer`) |
| `BypassOptions`, `BypassDialContext` | `BypassOptions`, `bypass_forward` |
| `relay.Start(d, relay.Options{})` | `proxykit::relay::start(d, Default::default())` |
| `gateway.Nova.Split/Apply/New` | `gateway::NOVA.split/apply/dialer` |
| `errors.Is(err, ErrAuth)`, `*OpError` | `err.kind() == ErrorKind::Auth`, `err.is(..)`, `err.stage()`, `err.status_code()` |
| `IsTimeout(err)` | `err.is_timeout()` |
| `context.Context` | отмена — drop future или `tokio::time::timeout`; таймауты в опциях |
| нулевое значение `time.Duration` = default | `Option<Duration>`: `None` = default |

`Spec` — обычная структура (`protocol`, `host`, `port: u16`, `username`, `password`),
`Display`/`Debug` скрывают credentials, `spec.url()` и serde их содержат намеренно.
`Spec` реализует `FromStr`: `"socks5://u:p@host:1080".parse::<Spec>()`.

## Форматы

Те же правила, что и в Go-версии, включая все 44 варианта `Layout` (24 перестановки
с `:`, 12 с `@` между host и port, 8 с `@` между парой credentials и endpoint):

| Вход | Значение |
|---|---|
| `host:port`, `host@port`, `port@host` | endpoint без авторизации |
| `host:port:login:pass`, `login:pass:host:port` | стандартные порядки |
| `login:pass@host:port`, `host:port@login:pass` | `@` между парами |
| `[2001:db8::1]@1080` | IPv6 |
| `http://`, `https://`, `socks5://` (`socks`, `socks5h`) | URL с percent-escaping |

```rust
use proxykit::{parse_with, ParseOptions, Protocol};

let spec = parse_with("host.example@1080:secret:alice", &ParseOptions {
    default_protocol: Protocol::Socks5,
    layout: "host@port:pass:login".into(),
})?;
assert_eq!((spec.username.as_str(), spec.password.as_str()), ("alice", "secret"));
```

`Layout::HOST_PORT_USER_PASS` и `Layout::USER_PASS_HOST_PORT` — готовые layout.
`host:123:user:456` без layout возвращает `ErrorKind::Ambiguous`.
`parse` не угадывает протокол по порту: без схемы протокол остаётся `Auto`,
и для `proxykit::new` нужен `Options::target`.

## TCP и HTTP

```rust
use proxykit::{Dialer, DialOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

let d = Dialer::new(proxykit::parse("socks5://user:pass@host:1080")?, DialOptions::default())?;
let mut tunnel = d.connect("149.154.167.50:443").await?;
tunnel.write_all(b"...").await?;

let client = d.http_client();
let resp = client.get("https://example.com/".parse()?).await?;
```

`Dialer` дёшево клонируется и безопасен для параллельного использования.
Таймаут установки (по умолчанию 10 с) охватывает TCP, TLS к прокси, авторизацию и CONNECT;
после возврата туннель принадлежит вызывающему коду, дедлайнов нет.
Байты, пришедшие от прокси сразу после ответа на CONNECT, сохраняются в туннеле.

`ProxyConnector` (`d.connector()`) — hyper-коннектор для своего клиента;
трейт `Connect` позволяет подставить любую реализацию туннеля.
Клиентам, которые принимают только URL прокси (например `reqwest`), удобно отдать
`relay::start(d, ..)?.url()`.

## Маршрут и TLS

```rust
use std::time::Duration;
use proxykit::{DialOptions, Forward};

let opts = DialOptions {
    timeout: Some(Duration::from_secs(8)),
    forward: Some(Forward::new(|addr| tokio::net::TcpStream::connect(addr))),
    tls: Some(my_rustls_config), // TLS к HTTPS-прокси
    ..Default::default()
};
```

`CheckOptions::tls` / `ProxyConnector::with_tls` относятся к целевому серверу.
По умолчанию сертификаты проверяются по встроенным корням Mozilla (`webpki-roots`);
для своих CA — `proxykit::tls::client_config_with_roots`.

### Обход VPN и WARP

```rust
let opts = DialOptions { bypass: Some(proxykit::BypassOptions::default()), ..Default::default() };
```

Как в Go-версии: привязка к физическому интерфейсу (macOS `IP_BOUND_IF`, `en*`;
Linux `SO_BINDTODEVICE`), DNS через публичные резолверы по тому же интерфейсу
с переходом на DNS over TLS, параллельные попытки со сдвигом 250 мс, без запасного пути
через туннель (`ErrorKind::NoInterface`). Loopback не привязывается.
Проверка на своей машине: `cargo run --example bypass` при включённом VPN.

**Windows пока не поддерживается** (`bypass_supported() == false`, `ErrorKind::BypassUnsupported`).

## Проверки, скорость, информация

```rust
use proxykit::{BatchOptions, CheckOptions, InspectOptions, SpeedTestOptions};

let r = d.check(CheckOptions::target("target.example:443")).await?;
let r = d.check(CheckOptions::url("https://host/health")).await?; // 2xx, без редиректов

let outcomes = proxykit::check_all(&specs, BatchOptions {
    check: CheckOptions::target("target.example:443"),
    concurrency: 16,
    ..Default::default()
}).await; // порядок сохраняется, у каждого свой error

let speed = proxykit::speed_test(&spec, SpeedTestOptions::url("https://speed.example/10mb")).await?;
// speed.health.ok, speed.speed.megabits_per_second, speed.speed.complete

let info = proxykit::inspect(&spec, InspectOptions {
    target: "web.telegram.org:443".into(),
    ..Default::default()
}).await?;
// info.proxy.protocol, info.latency, info.geo.country, info.geo.ip, info.geo_error
```

Геолокация по умолчанию — `https://ipwho.is/` через сам прокси (единственный внешний
запрос библиотеки); свой сервис — `InspectOptions::geo` (`GeoLookup::new`), отключить — `skip_geo`.

```rust
use proxykit::{ErrorKind, Stage};

match d.connect(target).await {
    Err(e) if e.kind() == ErrorKind::Auth => { /* credentials rejected */ }
    Err(e) if e.is_timeout() => { /* deadline */ }
    Err(e) => eprintln!("stage={:?} status={:?}: {e}", e.stage(), e.status_code()),
    Ok(tunnel) => { /* ... */ }
}
```

`Display` ошибок не содержит credentials, URL и текста удалённой стороны;
исходная причина доступна через `source()` и `Debug`.

## Ротационные прокси

```rust
use std::time::Duration;
use proxykit::gateway::{self, Params, NOVA};

let spec = proxykit::parse("http://acct1-country-RU-session-ab12cd34ef-time-1440:secret@gw.example:6969")?;
let (base, params) = NOVA.split(&spec)?;          // base.username == "acct1"
let sticky = NOVA.apply(&base, &Params {
    country: "DE".into(), session: gateway::new_session(), ttl: Duration::from_secs(1800),
})?;

let d = NOVA.dialer("gw.example:6969:acct1:secret",
    Params { country: "RU".into(), ttl: Duration::from_secs(86400), ..Default::default() },
    proxykit::Options { target: "web.telegram.org:443".into(), ..Default::default() }).await?;
```

Свой провайдер — значение `gateway::Format { separator, country, session, ttl, ttl_unit, in_password }`.

## Браузерный relay

```rust
let relay = proxykit::relay::start(d, Default::default())?;
// Chromium: --proxy-server=<relay.url()>
relay.close().await;
```

Только `127.0.0.1`, случайный порт, без локальной авторизации, максимум 128 активных
операций, таймаут заголовков 5 с. `close` закрывает слушатель, запросы и активные туннели.

## Примеры и тесты

```sh
cargo test                     # parse/layout, gateway, сетевые тесты на локальных фикстурах
cargo clippy --all-targets
PROXY_URL=... TARGET_ADDR=... cargo run --example tcp
PROXY_URL=... TARGET_URL=...  cargo run --example http
PROXY_URL=... TARGET_URL=...  cargo run --example speed
PROXY_URL=...                 cargo run --example browser
cargo run --example bypass -- [--iface en0] [proxy]
```

Тесты используют реальные локальные сокеты: SOCKS5 с авторизацией и без, HTTP CONNECT,
HTTPS-прокси с самоподписанным сертификатом, remote DNS, отказ цели, 407, таймауты,
байты после CONNECT, payload > 64 KiB, статусы и редиректы, speed test, batch, relay, inspect.
