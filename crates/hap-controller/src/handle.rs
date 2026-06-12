//! [`AccessoryHandle`]: one secure session to one accessory, plus a cached
//! accessory tree and an event stream.

use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::Stream;

use hap_model::{Accessory, CharValue, CharacteristicType, ServiceType};
use hap_transport::{EventNotification, HapResponse, SecureSession};

use crate::error::{HapError, Result};
use crate::event::{into_stream, CharacteristicEvent};

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
    ) -> Result<HapResponse>;

    /// Take the `EVENT/1.0` notification receiver. Valid once per session; later
    /// calls yield an already-closed receiver.
    fn take_events(&self) -> mpsc::Receiver<EventNotification>;
}

#[async_trait]
impl Session for SecureSession {
    async fn request(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<HapResponse> {
        // Disambiguate from this trait method: call the inherent method.
        Ok(SecureSession::request(self, method, path, content_type, body).await?)
    }

    fn take_events(&self) -> mpsc::Receiver<EventNotification> {
        self.events()
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
    session: Box<dyn Session>,
    accessories: Option<Vec<Accessory>>,
    events_tx: broadcast::Sender<CharacteristicEvent>,
}

impl AccessoryHandle {
    /// Build a handle around an established [`SecureSession`], wiring its
    /// `EVENT/1.0` channel into a broadcast fan-out. Crate-internal — used by
    /// the controller after Pair Verify. Must be called from within a Tokio
    /// runtime, since it spawns the event-pump task.
    pub(crate) fn connect(session: SecureSession) -> Self {
        Self::build(Box::new(session))
    }

    /// Build a handle around an arbitrary [`Session`] implementation. Hidden
    /// test seam — used by this crate's integration tests to wrap a mock.
    #[doc(hidden)]
    pub fn from_session(session: Box<dyn Session>) -> Self {
        Self::build(session)
    }

    /// Spawn the event pump and assemble the handle. Must be called from within
    /// a Tokio runtime, since it `tokio::spawn`s the event-pump task.
    fn build(session: Box<dyn Session>) -> Self {
        let (events_tx, _) = broadcast::channel(64);
        // Drain the transport's EVENT/1.0 mpsc receiver, decode each hap+json
        // push via hap-model, and fan it out over the broadcast channel.
        let mut event_rx = session.take_events();
        let tx = events_tx.clone();
        tokio::spawn(async move {
            while let Some(note) = event_rx.recv().await {
                // An EVENT body has the same shape as a /characteristics read
                // response (a list of {aid, iid, value}); reuse that decoder.
                if let Ok(reports) = hap_model::parse_read_response(&note.body) {
                    for ((aid, iid), value) in reports {
                        // Send error only means there are no live receivers yet.
                        let _ = tx.send(CharacteristicEvent { aid, iid, value });
                    }
                }
            }
            // Channel closed: the session is gone. The task ends and the
            // broadcast sender it held drops.
        });
        Self {
            session,
            accessories: None,
            events_tx,
        }
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
        if self.accessories.is_none() {
            let resp = self
                .session
                .request("GET", "/accessories", "application/hap+json", b"")
                .await?;
            if !is_success(resp.status) {
                return Err(HapError::Http {
                    status: resp.status,
                });
            }
            let parsed = hap_model::parse_accessories(&resp.body)?;
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

    /// Read one characteristic's current value.
    ///
    /// # Errors
    ///
    /// [`HapError::Transport`] on a session failure, [`HapError::Http`] on a
    /// non-success status, or [`HapError::Model`] if the response cannot be
    /// decoded (including a non-zero per-characteristic HAP status).
    pub async fn read(&mut self, aid: u64, iid: u64) -> Result<CharValue> {
        let path = hap_model::build_read_request(&[(aid, iid)]);
        let resp = self
            .session
            .request("GET", &path, "application/hap+json", b"")
            .await?;
        if !is_success(resp.status) {
            return Err(HapError::Http {
                status: resp.status,
            });
        }
        let mut values = hap_model::parse_read_response(&resp.body)?;
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
        let body = hap_model::build_write_request(&[((aid, iid), value)]);
        self.put_characteristics(&body).await
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
        self.put_characteristics(&body).await
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

    /// Shared `PUT /characteristics` path for `write` and `subscribe`: send the
    /// body, reject non-success HTTP, and surface any per-characteristic failure
    /// the accessory lists in a 207 Multi-Status body.
    async fn put_characteristics(&self, body: &[u8]) -> Result<()> {
        let resp = self
            .session
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
