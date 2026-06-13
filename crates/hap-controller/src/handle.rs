//! [`AccessoryHandle`]: one secure session to one accessory, plus a cached
//! accessory tree and an event stream.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::Stream;

use hap_model::{Accessory, CharFormat, CharValue, CharacteristicType, ServiceType};
use hap_transport::SecureSession;

use crate::error::{HapError, Result};
use crate::event::{into_stream, CharacteristicEvent};
use crate::reconnect::{backoff, ConnectionState, Reconnected, ReconnectingSession, Reconnector};

/// Default per-request timeout applied to every new [`AccessoryHandle`].
///
/// A foreground operation (read, write, subscribe) that receives no response
/// within this window fails with [`HapError::ConnectionLost`] rather than
/// hanging until TCP's own timeout fires.
pub(crate) const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `(aid, iid)` → declared characteristic format, learned from `/accessories`.
/// Shared with the event pump so it can decode `EVENT/1.0` values (which carry
/// no `format`) with their true type instead of falling back to inference.
type FormatMap = Arc<Mutex<HashMap<(u64, u64), CharFormat>>>;

/// The status + body of a session response. A seam-local type so the [`Session`]
/// trait does not leak `hap-transport`'s (non-exhaustive) response struct.
#[doc(hidden)]
pub struct SessionResponse {
    /// HTTP status the accessory returned.
    pub status: u16,
    /// Raw response body bytes.
    pub body: Vec<u8>,
}

/// The transport seam used by [`AccessoryHandle`] for HTTP-style requests and
/// the `EVENT/1.0` notification channel.
///
/// This exists so the handle's `read`/`write`/`subscribe`/`events` logic can be
/// exercised against an in-memory double instead of a live accessory. It is
/// implemented for [`hap_transport::SecureSession`] (the real transport) and
/// for the test doubles. **Not part of the supported public API.**
#[doc(hidden)]
#[async_trait]
pub trait Session: Send + Sync {
    /// Send one encrypted HTTP request over the session and await the response.
    ///
    /// # Errors
    ///
    /// Returns [`HapError::Transport`] if the request or response fails on the
    /// record/HTTP layer.
    async fn request(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<SessionResponse>;

    /// Take the `EVENT/1.0` notification receiver, each item a raw hap+json
    /// event body. Valid once per session; later calls yield a closed receiver.
    fn take_events(&self) -> mpsc::Receiver<Vec<u8>>;
}

#[async_trait]
impl Session for SecureSession {
    async fn request(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<SessionResponse> {
        // Disambiguate from this trait method: call the inherent method.
        let resp = SecureSession::request(self, method, path, content_type, body).await?;
        Ok(SessionResponse {
            status: resp.status,
            body: resp.body,
        })
    }

    fn take_events(&self) -> mpsc::Receiver<Vec<u8>> {
        // Forward the transport's EventNotification stream as raw bodies, so the
        // seam carries `Vec<u8>` and stays free of transport-internal types.
        let mut src = self.events();
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            while let Some(note) = src.recv().await {
                if tx.send(note.body).await.is_err() {
                    break;
                }
            }
        });
        rx
    }
}

/// A live, secure connection to a single accessory.
///
/// Obtain one from [`crate::HapController::pair`] or
/// [`crate::HapController::connect`]. Methods that touch the network take
/// `&mut self` because they mutate the cached accessory tree; the event
/// [`Stream`] from [`AccessoryHandle::events`] can be held concurrently because
/// it is fed by a broadcast channel.
pub struct AccessoryHandle {
    conn: Arc<ReconnectingSession>,
    accessories: Option<Vec<Accessory>>,
    events_tx: broadcast::Sender<CharacteristicEvent>,
    formats: FormatMap,
    subscribed: Arc<Mutex<HashSet<(u64, u64)>>>,
    pid: Arc<AtomicU64>,
    needs_refresh: Arc<AtomicBool>,
}

/// A no-op [`Reconnector`] for the single-session test seam: it is wired in but
/// never actually called unless the lone session dies, in which case there is
/// nothing to reconnect to.
struct NoReconnect;

#[async_trait]
impl Reconnector for NoReconnect {
    async fn reconnect(&self) -> Result<Reconnected> {
        Err(HapError::ConnectionLost)
    }
}

impl AccessoryHandle {
    /// Build a handle from an established session plus a [`Reconnector`] that can
    /// re-establish it. Crate-internal — used by the controller after Pair
    /// Verify. Must be called from within a Tokio runtime, since it spawns the
    /// supervisor task that owns reconnection and the event pump.
    pub(crate) fn connect(
        session: Arc<dyn Session>,
        reconnector: Box<dyn Reconnector>,
        request_timeout: std::time::Duration,
    ) -> Self {
        Self::build(session, reconnector, request_timeout)
    }

    /// Build a handle around an arbitrary [`Session`] with no reconnection.
    /// Hidden test seam — used by this crate's integration tests to wrap a mock.
    #[doc(hidden)]
    pub fn from_session(session: Box<dyn Session>) -> Self {
        Self::build(
            Arc::from(session),
            Box::new(NoReconnect),
            DEFAULT_REQUEST_TIMEOUT,
        )
    }

    /// Build a handle around a session plus a custom [`Reconnector`]. Hidden test
    /// seam — used by the reconnect tests to drive a controlled reconnector.
    #[doc(hidden)]
    pub fn from_parts(session: Arc<dyn Session>, reconnector: Box<dyn Reconnector>) -> Self {
        Self::build(session, reconnector, DEFAULT_REQUEST_TIMEOUT)
    }

    /// Assemble the handle and spawn the supervisor task. Must be called from
    /// within a Tokio runtime, since it `tokio::spawn`s that task.
    ///
    /// A single supervisor task owns all reconnection: it drains the current
    /// session's `EVENT/1.0` channel, and on session death reconnects (with
    /// indefinite backoff), re-issues subscriptions, then publishes the fresh
    /// session for foreground ops to pick up. Foreground ops never reconnect
    /// themselves — they only wait for a restored session — so reconnection is
    /// race-free by construction.
    fn build(
        session: Arc<dyn Session>,
        reconnector: Box<dyn Reconnector>,
        request_timeout: std::time::Duration,
    ) -> Self {
        let (events_tx, _) = broadcast::channel(64);
        let formats: FormatMap = Arc::new(Mutex::new(HashMap::new()));
        let subscribed: Arc<Mutex<HashSet<(u64, u64)>>> = Arc::new(Mutex::new(HashSet::new()));
        let needs_refresh = Arc::new(AtomicBool::new(false));
        let conn = Arc::new(ReconnectingSession::new(
            session,
            reconnector,
            request_timeout,
        ));

        let pump = conn.clone();
        let tx = events_tx.clone();
        let fmt = formats.clone();
        let subs = subscribed.clone();
        let refresh = needs_refresh.clone();
        tokio::spawn(async move {
            let mut last_cn: Option<u32> = None;
            loop {
                let sess = pump.current();
                pump.set_state(ConnectionState::Connected);
                let mut rx = sess.take_events();
                // Drain the current session's EVENT/1.0 channel. An EVENT body
                // has the same shape as a /characteristics read response (a list
                // of {aid, iid, value}); reuse that decoder.
                while let Some(body) = rx.recv().await {
                    if let Ok(reports) = hap_model::parse_read_response(&body) {
                        for ((aid, iid), value) in reports {
                            // EVENT bodies omit `format`, so the decoder infers
                            // the type (a bool `0` becomes Uint). Re-coerce to
                            // the characteristic's declared format if we learned
                            // it from a prior `/accessories` fetch.
                            let f = fmt.lock().ok().and_then(|m| m.get(&(aid, iid)).copied());
                            let value = match f {
                                Some(x) => coerce_to_format(value, x),
                                None => value,
                            };
                            // Send error only means there are no live receivers.
                            let _ = tx.send(CharacteristicEvent { aid, iid, value });
                        }
                    }
                }

                // Session died. Reconnect with indefinite backoff.
                pump.set_state(ConnectionState::Disconnected);
                let mut attempt: u32 = 0;
                let rc = loop {
                    attempt += 1;
                    pump.set_state(ConnectionState::Reconnecting { attempt });
                    match pump.reconnect().await {
                        Ok(rc) => break rc,
                        Err(_) => tokio::time::sleep(backoff(attempt)).await,
                    }
                };

                // c# refresh: invalidate the cached DB if the config number
                // changed across the reconnect.
                if let Some(new_cn) = rc.config_number {
                    if last_cn.is_some() && last_cn != Some(new_cn) {
                        refresh.store(true, Ordering::Relaxed);
                    }
                    last_cn = Some(new_cn);
                }

                // Re-subscribe on the fresh session before publishing it, so a
                // foreground waiter that wakes on the new session already has its
                // subscriptions in place.
                let ids: Vec<(u64, u64)> = subs
                    .lock()
                    .map(|s| s.iter().copied().collect())
                    .unwrap_or_default();
                for (aid, iid) in ids {
                    let b = hap_model::build_subscribe_request(&[(aid, iid)], true);
                    let _ = rc
                        .session
                        .request("PUT", "/characteristics", "application/hap+json", &b)
                        .await;
                }

                pump.publish(rc.session.clone());
                // Loop: drain the freshly published session's events.
            }
        });

        Self {
            conn,
            accessories: None,
            events_tx,
            formats,
            subscribed,
            pid: Arc::new(AtomicU64::new(1)),
            needs_refresh,
        }
    }

    /// Single point where every request leaves the handle. Routes through the
    /// reconnecting session, which transparently waits out a reconnect if the
    /// current session is dead.
    async fn request(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<SessionResponse> {
        self.conn.request(method, path, content_type, body).await
    }

    /// Fetch (and cache) the accessory attribute database.
    ///
    /// The first call reads `/accessories` over the session and parses it via
    /// `hap-model`; subsequent calls return the cached tree. Call again after a
    /// config-number (`c#`) change to refresh.
    ///
    /// # Errors
    ///
    /// [`HapError::Transport`] if the read fails, [`HapError::Http`] if the
    /// accessory returns a non-success status, or [`HapError::Model`] if the
    /// JSON cannot be parsed.
    pub async fn accessories(&mut self) -> Result<&[Accessory]> {
        // A reconnect that observed a config-number (`c#`) change requests a
        // refresh; drop the cached tree so it is re-fetched below.
        if self.needs_refresh.swap(false, Ordering::Relaxed) {
            self.accessories = None;
        }
        if self.accessories.is_none() {
            let resp = self
                .request("GET", "/accessories", "application/hap+json", b"")
                .await?;
            if !is_success(resp.status) {
                return Err(HapError::Http {
                    status: resp.status,
                });
            }
            let parsed = hap_model::parse_accessories(&resp.body)?;
            // Record each characteristic's declared format so the event pump can
            // decode formatless EVENT/1.0 values with their true type.
            if let Ok(mut map) = self.formats.lock() {
                map.clear();
                for acc in &parsed {
                    for svc in &acc.services {
                        for ch in &svc.characteristics {
                            map.insert((acc.aid, ch.iid), ch.format);
                        }
                    }
                }
            }
            self.accessories = Some(parsed);
        }
        // Just populated above if it was `None`; `unwrap_or` keeps this panic-free.
        Ok(self.accessories.as_deref().unwrap_or(&[]))
    }

    /// Find the `(aid, iid)` of the first characteristic matching `service` +
    /// `characteristic` types anywhere in the cached tree.
    ///
    /// Requires [`accessories`](Self::accessories) to have been called first.
    ///
    /// # Errors
    ///
    /// [`HapError::CharacteristicNotFound`] if no match exists in the cache.
    // Take the type enums by value for caller ergonomics — `find(ServiceType::
    // Outlet, CharacteristicType::On)` reads better than threading references.
    #[allow(clippy::needless_pass_by_value)]
    pub fn find(
        &self,
        service: ServiceType,
        characteristic: CharacteristicType,
    ) -> Result<(u64, u64)> {
        let tree = self.accessories.as_deref().unwrap_or(&[]);
        for accessory in tree {
            for svc in &accessory.services {
                if svc.service_type != service {
                    continue;
                }
                for ch in &svc.characteristics {
                    if ch.char_type == characteristic {
                        return Ok((accessory.aid, ch.iid));
                    }
                }
            }
        }
        Err(HapError::CharacteristicNotFound { aid: 0, iid: 0 })
    }

    /// Read several characteristics in one request.
    ///
    /// Values are typed from the cached accessory database (the read itself does
    /// not request `meta=1`), so call [`accessories`](Self::accessories) first to
    /// get fully-typed values; without it, numeric/bool values fall back to JSON
    /// inference (e.g. an `int` may surface as `Uint`).
    ///
    /// # Errors
    ///
    /// [`HapError::Transport`]/[`HapError::Http`] on the request, [`HapError::Model`]
    /// if any entry fails to decode (including a non-zero per-characteristic status).
    pub async fn read_many(&mut self, ids: &[(u64, u64)]) -> Result<Vec<((u64, u64), CharValue)>> {
        let path = hap_model::build_read_request(ids);
        let resp = self
            .request("GET", &path, "application/hap+json", b"")
            .await?;
        if !is_success(resp.status) {
            return Err(HapError::Http {
                status: resp.status,
            });
        }
        let parsed = hap_model::parse_read_response(&resp.body)?;
        // The read omits `meta=1`, so values are inferred from JSON. Re-type each
        // to its declared format from the cached accessory DB (same coercion the
        // event pump applies).
        Ok(parsed
            .into_iter()
            .map(|((aid, iid), value)| {
                let fmt = self
                    .formats
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&(aid, iid)).copied());
                let value = match fmt {
                    Some(f) => coerce_to_format(value, f),
                    None => value,
                };
                ((aid, iid), value)
            })
            .collect())
    }

    /// Write several characteristics in one request.
    ///
    /// # Errors
    ///
    /// [`HapError::Transport`]/[`HapError::Http`] on the request, [`HapError::Model`]
    /// on a per-characteristic failure (207 Multi-Status body).
    pub async fn write_many(&mut self, writes: &[((u64, u64), CharValue)]) -> Result<()> {
        let body = hap_model::build_write_request(writes);
        self.put_characteristics(&body).await
    }

    /// Read one characteristic's current value.
    ///
    /// # Errors
    ///
    /// [`HapError::Transport`] on a session failure, [`HapError::Http`] on a
    /// non-success status, or [`HapError::Model`] if the response cannot be
    /// decoded (including a non-zero per-characteristic HAP status).
    pub async fn read(&mut self, aid: u64, iid: u64) -> Result<CharValue> {
        let mut values = self.read_many(&[(aid, iid)]).await?;
        if values.is_empty() {
            return Err(HapError::CharacteristicNotFound { aid, iid });
        }
        Ok(values.remove(0).1)
    }

    /// Write one characteristic.
    ///
    /// # Errors
    ///
    /// [`HapError::Transport`] on a session failure, [`HapError::Http`] on a
    /// non-success status, or [`HapError::Model`] if the accessory reports a
    /// non-zero per-characteristic status (HTTP 207 Multi-Status body).
    pub async fn write(&mut self, aid: u64, iid: u64, value: CharValue) -> Result<()> {
        self.write_many(&[((aid, iid), value)]).await
    }

    /// Subscribe to change events for one characteristic. Events then arrive on
    /// the [`events`](Self::events) stream.
    ///
    /// # Errors
    ///
    /// [`HapError::Transport`] if the subscribe write fails, [`HapError::Http`]
    /// on a non-success status, or [`HapError::Model`] on a per-characteristic
    /// failure.
    pub async fn subscribe(&mut self, aid: u64, iid: u64) -> Result<()> {
        let body = hap_model::build_subscribe_request(&[(aid, iid)], true);
        self.put_characteristics(&body).await?;
        // Record the id so the supervisor can re-issue it after a reconnect.
        if let Ok(mut s) = self.subscribed.lock() {
            s.insert((aid, iid));
        }
        Ok(())
    }

    /// Stop receiving change events for a characteristic.
    ///
    /// # Errors
    ///
    /// [`HapError::Transport`]/[`HapError::Http`] on the request, [`HapError::Model`]
    /// on a per-characteristic failure.
    pub async fn unsubscribe(&mut self, aid: u64, iid: u64) -> Result<()> {
        let body = hap_model::build_subscribe_request(&[(aid, iid)], false);
        self.put_characteristics(&body).await?;
        if let Ok(mut s) = self.subscribed.lock() {
            s.remove(&(aid, iid));
        }
        Ok(())
    }

    /// A stream of [`ConnectionState`] transitions, for health reporting.
    ///
    /// Each call returns an independent receiver; transitions that arrive while
    /// a particular stream is lagging are dropped for that stream.
    pub fn connection_state(&self) -> impl Stream<Item = ConnectionState> {
        crate::event::into_broadcast_stream(self.conn.subscribe_state())
    }

    /// An async stream of [`CharacteristicEvent`]s for every characteristic this
    /// handle has [`subscribe`](Self::subscribe)d to.
    ///
    /// Multiple streams may be held at once; each is an independent broadcast
    /// receiver. Events that arrive while a particular stream is lagging are
    /// dropped for that stream.
    pub fn events(&self) -> impl Stream<Item = CharacteristicEvent> {
        into_stream(self.events_tx.subscribe())
    }

    /// Timed write: reserve with `PUT /prepare {ttl,pid}` then write carrying that
    /// pid, completing within `ttl`. For security-sensitive accessories (locks).
    ///
    /// # Errors
    ///
    /// [`HapError::Transport`]/[`HapError::Http`] on either request, [`HapError::Model`]
    /// on a per-characteristic failure.
    pub async fn write_timed(
        &mut self,
        aid: u64,
        iid: u64,
        value: CharValue,
        ttl: std::time::Duration,
    ) -> Result<()> {
        let pid = self.pid.fetch_add(1, Ordering::Relaxed);
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        let prepare = hap_model::build_prepare_request(ttl_ms, pid);
        let resp = self
            .request("PUT", "/prepare", "application/hap+json", &prepare)
            .await?;
        if !is_success(resp.status) {
            return Err(HapError::Http {
                status: resp.status,
            });
        }
        let body = hap_model::build_timed_write_request(&[((aid, iid), value)], pid);
        self.put_characteristics(&body).await
    }

    /// Write requesting the post-write value back (the HAP `r` flag).
    ///
    /// The `r` flag is optional in HAP: accessories that don't support it reject
    /// the write with a per-characteristic status (surfaced as [`HapError::Model`]).
    /// Some shipping firmware (e.g. LIFX) declines it with status `-70405`.
    ///
    /// # Errors
    ///
    /// [`HapError::Transport`]/[`HapError::Http`] on the request, [`HapError::Model`]
    /// if the response cannot be decoded or the accessory rejects the read-response,
    /// [`HapError::CharacteristicNotFound`] if the accessory returns no value.
    pub async fn write_with_response(
        &mut self,
        aid: u64,
        iid: u64,
        value: CharValue,
    ) -> Result<CharValue> {
        let body = hap_model::build_write_request_with_response(&[((aid, iid), value)]);
        let resp = self
            .request("PUT", "/characteristics", "application/hap+json", &body)
            .await?;
        if !is_success(resp.status) {
            return Err(HapError::Http {
                status: resp.status,
            });
        }
        let mut v = hap_model::parse_read_response(&resp.body)?;
        if v.is_empty() {
            return Err(HapError::CharacteristicNotFound { aid, iid });
        }
        let value = v.remove(0).1;
        // Re-type to the declared format from the cached DB, like `read_many`.
        let fmt = self
            .formats
            .lock()
            .ok()
            .and_then(|m| m.get(&(aid, iid)).copied());
        Ok(match fmt {
            Some(f) => coerce_to_format(value, f),
            None => value,
        })
    }

    /// Shared `PUT /characteristics` path for `write` and `subscribe`: send the
    /// body, reject non-success HTTP, and surface any per-characteristic failure
    /// the accessory lists in a 207 Multi-Status body.
    async fn put_characteristics(&self, body: &[u8]) -> Result<()> {
        let resp = self
            .request("PUT", "/characteristics", "application/hap+json", body)
            .await?;
        if !is_success(resp.status) {
            return Err(HapError::Http {
                status: resp.status,
            });
        }
        if !resp.body.is_empty() {
            // 207 Multi-Status: the body lists per-characteristic failures.
            // `parse_read_response` turns any non-zero status into an error.
            hap_model::parse_read_response(&resp.body)?;
        }
        Ok(())
    }
}

/// Whether an HTTP status is in the 2xx success range.
fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Re-type an inferred event value to the characteristic's declared format.
///
/// EVENT/1.0 bodies omit `format`, so `parse_read_response` infers numeric/bool
/// values from the JSON (a bool `0` becomes `Uint(0)`). Given the real format
/// from `/accessories`, narrow the value back to its proper variant. Non-numeric
/// formats and already-correct values pass through unchanged.
#[allow(clippy::cast_precision_loss)] // HAP numeric values are far below 2^53
fn coerce_to_format(value: CharValue, fmt: CharFormat) -> CharValue {
    match (fmt, value) {
        (CharFormat::Bool, CharValue::Uint(n)) => CharValue::Bool(n != 0),
        (CharFormat::Bool, CharValue::Int(n)) => CharValue::Bool(n != 0),
        (CharFormat::Int, CharValue::Uint(n)) => {
            i64::try_from(n).map_or(CharValue::Uint(n), CharValue::Int)
        }
        (CharFormat::Float, CharValue::Uint(n)) => CharValue::Float(n as f64),
        (CharFormat::Float, CharValue::Int(n)) => CharValue::Float(n as f64),
        (_, other) => other,
    }
}

#[cfg(test)]
mod tests {
    use super::{coerce_to_format, CharFormat, CharValue};

    #[test]
    fn bool_event_inferred_as_uint_is_narrowed_to_bool() {
        assert_eq!(
            coerce_to_format(CharValue::Uint(0), CharFormat::Bool),
            CharValue::Bool(false)
        );
        assert_eq!(
            coerce_to_format(CharValue::Uint(1), CharFormat::Bool),
            CharValue::Bool(true)
        );
    }

    #[test]
    fn int_and_float_are_narrowed_from_uint() {
        assert_eq!(
            coerce_to_format(CharValue::Uint(50), CharFormat::Int),
            CharValue::Int(50)
        );
        assert_eq!(
            coerce_to_format(CharValue::Uint(23), CharFormat::Float),
            CharValue::Float(23.0)
        );
    }

    #[test]
    fn matching_or_unknown_formats_pass_through() {
        // Already the right variant.
        assert_eq!(
            coerce_to_format(CharValue::Bool(true), CharFormat::Bool),
            CharValue::Bool(true)
        );
        // String format is left to inference.
        assert_eq!(
            coerce_to_format(CharValue::Str("x".into()), CharFormat::String),
            CharValue::Str("x".into())
        );
    }
}
