// NaviCore Uzak Destek: baglanti BASLATAN istemcinin giris yapmis olmasini zorunlu kilar.
//
// Istemci, API girisinden aldigi access_token'i PunchHoleRequest.token / RequestRelay.token ile gonderir
// (rustdesk istemcisi ui_session_interface.rs). Bu modul token'i yerel adres defteri API'sine sorar:
//   POST http://127.0.0.1:21114/api/internal/verify-token  {"token": "..."}  -> 200 = gecerli
// Ayar (ortam degiskeni, /opt/rustdesk/rustdesk.conf):
//   RD_REQUIRE_LOGIN=1          -> kontrol acik (yoksa/0 -> eski davranis, kontrol yok)
//   RD_VERIFY_URL=<url>         -> dogrulama adresi (varsayilan yukaridaki)
// Onbellek: gecerli 60 sn, gecersiz 15 sn. API'ye ulasilamazsa son 24 saatte dogrulanmis token kabul edilir
// (API kesintisinde destek verilebilsin); hic dogrulanmamis token reddedilir.
// Musteri cihazlari baglanti baslatmadigi icin (yalniz kabul eder) etkilenmez.

use hbb_common::{log, tokio::sync::Mutex};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

const OK_TTL: Duration = Duration::from_secs(60);
const FAIL_TTL: Duration = Duration::from_secs(15);
const GRACE: Duration = Duration::from_secs(24 * 3600);
const MAX_ENTRIES: usize = 10_000;
pub const DENY_MESSAGE: &str =
    "Bu sunucu yalnız NaviCore destek hesabıyla giriş yapmış kullanıcılara açıktır. Adres Defteri → Giriş yap.";

struct Entry {
    ok: bool,
    checked: Instant,
    last_ok: Option<Instant>,
}

lazy_static::lazy_static! {
    static ref CACHE: Mutex<HashMap<String, Entry>> = Mutex::new(HashMap::new());
    static ref ENABLED: bool = matches!(std::env::var("RD_REQUIRE_LOGIN").as_deref(), Ok("1") | Ok("Y") | Ok("y"));
    static ref VERIFY_URL: String = std::env::var("RD_VERIFY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:21114/api/internal/verify-token".to_owned());
}

pub fn enabled() -> bool {
    *ENABLED
}

pub fn log_startup() {
    if enabled() {
        log::info!("NaviCore: baglanti baslatmak icin giris zorunlu (dogrulama: {})", *VERIFY_URL);
    } else {
        log::info!("NaviCore: giris zorunlulugu KAPALI (RD_REQUIRE_LOGIN ayarlanmamis)");
    }
}

/// None = API'ye ulasilamadi (ag/zaman asimi/5xx), Some(b) = kesin cevap.
async fn ask_api(token: &str) -> Option<bool> {
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(3)).build() {
        Ok(c) => c,
        Err(_) => return None,
    };
    let body = serde_json::json!({ "token": token }).to_string();
    match client
        .post(VERIFY_URL.as_str())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => Some(true),
        Ok(r) if r.status().as_u16() == 401 || r.status().as_u16() == 403 => Some(false),
        _ => None,
    }
}

/// Token bu sunucuda baglanti baslatmaya yetkili mi?
pub async fn token_ok(token: &str) -> bool {
    if token.is_empty() || token.len() > 256 {
        return false;
    }
    {
        let cache = CACHE.lock().await;
        if let Some(e) = cache.get(token) {
            let ttl = if e.ok { OK_TTL } else { FAIL_TTL };
            if e.checked.elapsed() < ttl {
                return e.ok;
            }
        }
    }
    let answer = ask_api(token).await;
    let mut cache = CACHE.lock().await;
    if cache.len() > MAX_ENTRIES {
        cache.retain(|_, e| e.checked.elapsed() < GRACE);
    }
    let prev_ok = cache.get(token).and_then(|e| e.last_ok);
    let ok = match answer {
        Some(b) => b,
        None => {
            let grace = prev_ok.map(|t| t.elapsed() < GRACE).unwrap_or(false);
            log::warn!("NaviCore: dogrulama API'sine ulasilamadi; onceki dogrulama ile {}", if grace { "kabul" } else { "red" });
            grace
        }
    };
    let now = Instant::now();
    cache.insert(
        token.to_owned(),
        Entry { ok, checked: now, last_ok: if answer == Some(true) { Some(now) } else if answer == Some(false) { None } else { prev_ok } },
    );
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> hbb_common::tokio::runtime::Runtime {
        hbb_common::tokio::runtime::Runtime::new().unwrap()
    }

    // Yerel API (127.0.0.1:21114) calisirken anlamli. NAVICORE_TEST_TOKEN verilirse gecerli token da sinanir.
    #[test]
    fn bos_ve_uydurma_token_reddedilir() {
        rt().block_on(async {
            assert!(!token_ok("").await);
            assert!(!token_ok(&"x".repeat(300)).await);
            if std::net::TcpStream::connect("127.0.0.1:21114").is_ok() {
                assert!(!token_ok("uydurma-token-123").await);
            }
        });
    }

    #[test]
    fn gecerli_token_kabul_edilir() {
        if let Ok(t) = std::env::var("NAVICORE_TEST_TOKEN") {
            rt().block_on(async {
                assert!(token_ok(&t).await, "gecerli token reddedildi");
                assert!(token_ok(&t).await, "onbellekten ikinci cagri reddedildi");
            });
        }
    }
}
