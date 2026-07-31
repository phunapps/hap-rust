//! The transport-unified [`AccessoryHandle`]: enum dispatch over the IP
//! handle ([`IpHandle`]) and (with the `ble` feature) [`hap_ble::BleAccessory`].

use crate::error::Result;
use crate::event::CharacteristicEvent;
use crate::handle::IpHandle;
use crate::reconnect::ConnectionState;
use hap_model::format::CharValue;
use hap_model::tree::Accessory;
use hap_model::{CharacteristicType, ServiceType};
use std::pin::Pin;
use tokio_stream::Stream;
#[cfg(feature = "ble")]
use tokio_stream::StreamExt as _;

/// A connected accessory on either transport. Obtained from
/// [`HapController::pair`](crate::HapController::pair) or
/// [`HapController::connect`](crate::HapController::connect).
///
/// Operations that exist on only one transport return
/// [`HapError::UnsupportedByTransport`](crate::HapError::UnsupportedByTransport) when called on the other: today that
/// is `unsubscribe`, `write_timed`, and `write_with_response` over BLE, and
/// `enable_broadcasts`/`watch_sleepy_events` over IP.
pub struct AccessoryHandle {
    inner: Inner,
}

enum Inner {
    Ip(IpHandle),
    #[cfg(feature = "ble")]
    Ble(hap_ble::BleAccessory),
}

impl AccessoryHandle {
    /// Wrap an IP handle. Crate-internal — used by [`crate::HapController`]
    /// after a successful connect/pair over IP.
    pub(crate) fn from_ip(h: IpHandle) -> Self {
        Self {
            inner: Inner::Ip(h),
        }
    }

    /// Wrap a BLE handle. Crate-internal — used by [`crate::HapController`]
    /// after a successful connect/pair over BLE.
    #[cfg(feature = "ble")]
    pub(crate) fn from_ble(b: hap_ble::BleAccessory) -> Self {
        Self {
            inner: Inner::Ble(b),
        }
    }

    // ── preserved doc-hidden IP constructors (integration-test seam) ──

    /// Build a handle around an arbitrary [`Session`](crate::Session) with no
    /// reconnection. Hidden test seam — used by this crate's integration
    /// tests to wrap a mock IP session. Always builds the IP variant.
    #[doc(hidden)]
    #[must_use]
    pub fn from_session(session: Box<dyn crate::handle::Session>) -> Self {
        Self::from_ip(IpHandle::from_session(session))
    }

    /// Build a handle around a session plus a custom
    /// [`Reconnector`](crate::Reconnector). Hidden test seam — used by the
    /// reconnect tests to drive a controlled reconnector. Always builds the
    /// IP variant.
    #[doc(hidden)]
    #[must_use]
    pub fn from_parts(
        session: std::sync::Arc<dyn crate::handle::Session>,
        reconnector: Box<dyn crate::reconnect::Reconnector>,
    ) -> Self {
        Self::from_ip(IpHandle::from_parts(session, reconnector))
    }

    /// Wrap a BLE handle for this crate's `ble` integration tests. Hidden test
    /// seam (semver-exempt), mirroring [`AccessoryHandle::from_session`] for
    /// the IP path — `from_ble` itself is `pub(crate)` and invisible to an
    /// integration-test crate.
    #[doc(hidden)]
    #[cfg(feature = "ble")]
    #[must_use]
    pub fn from_ble_for_tests(inner: hap_ble::BleAccessory) -> Self {
        Self::from_ble(inner)
    }

    /// Fetch (IP) or return the cached (BLE) accessory database.
    ///
    /// On IP the first call reads `/accessories` over the session and caches
    /// it; call again after a config-number (`c#`) change to refresh. On BLE
    /// the database is fetched once at connect time (before Pair Verify) and
    /// this always returns that cache.
    ///
    /// # Errors
    ///
    /// IP: [`HapError::Transport`](crate::HapError::Transport) if the read fails, [`HapError::Http`](crate::HapError::Http) on a
    /// non-success status, or [`HapError::Model`](crate::HapError::Model) if the JSON cannot be
    /// parsed. BLE: never errors.
    pub async fn accessories(&mut self) -> Result<&[Accessory]> {
        match &mut self.inner {
            Inner::Ip(h) => h.accessories().await,
            #[cfg(feature = "ble")]
            Inner::Ble(b) => Ok(b.accessories()),
        }
    }

    /// Find the `(aid, iid)` of the first characteristic matching `svc` +
    /// `chr` types anywhere in the cached tree.
    ///
    /// Requires [`accessories`](Self::accessories) to have been called first
    /// (IP) — the BLE cache is always populated.
    ///
    /// # Errors
    ///
    /// [`HapError::CharacteristicNotFound`](crate::HapError::CharacteristicNotFound) if no match exists in the cache.
    pub fn find(&self, svc: ServiceType, chr: CharacteristicType) -> Result<(u64, u64)> {
        match &self.inner {
            Inner::Ip(h) => h.find(svc, chr),
            #[cfg(feature = "ble")]
            Inner::Ble(b) => Ok(b.find(svc, chr)?),
        }
    }

    /// Read one characteristic's current value.
    ///
    /// # Errors
    ///
    /// IP: [`HapError::Transport`](crate::HapError::Transport) on a session failure, [`HapError::Http`](crate::HapError::Http)
    /// on a non-success status, or [`HapError::Model`](crate::HapError::Model) if the response cannot
    /// be decoded. BLE: [`HapError::Ble`](crate::HapError::Ble) on a GATT/PDU/crypto failure or an
    /// unknown characteristic.
    pub async fn read(&mut self, aid: u64, iid: u64) -> Result<CharValue> {
        match &mut self.inner {
            Inner::Ip(h) => h.read(aid, iid).await,
            #[cfg(feature = "ble")]
            Inner::Ble(b) => Ok(b.read(aid, iid).await?),
        }
    }

    /// Write one characteristic.
    ///
    /// # Errors
    ///
    /// IP: [`HapError::Transport`](crate::HapError::Transport) on a session failure, [`HapError::Http`](crate::HapError::Http)
    /// on a non-success status, or [`HapError::Model`](crate::HapError::Model) on a per-characteristic
    /// failure. BLE: [`HapError::Ble`](crate::HapError::Ble) on a GATT/PDU/crypto failure, an
    /// unknown characteristic, or a non-zero PDU status.
    pub async fn write(&mut self, aid: u64, iid: u64, value: CharValue) -> Result<()> {
        match &mut self.inner {
            Inner::Ip(h) => h.write(aid, iid, value).await,
            #[cfg(feature = "ble")]
            Inner::Ble(b) => Ok(b.write(aid, iid, value).await?),
        }
    }

    /// Subscribe to change events for one characteristic. Events then arrive
    /// on the [`events`](Self::events) stream.
    ///
    /// # Errors
    ///
    /// IP: [`HapError::Transport`](crate::HapError::Transport) if the subscribe write fails,
    /// [`HapError::Http`](crate::HapError::Http) on a non-success status, or [`HapError::Model`](crate::HapError::Model) on
    /// a per-characteristic failure. BLE: [`HapError::Ble`](crate::HapError::Ble) if the
    /// characteristic is unknown or the GATT subscription fails.
    pub async fn subscribe(&mut self, aid: u64, iid: u64) -> Result<()> {
        match &mut self.inner {
            Inner::Ip(h) => h.subscribe(aid, iid).await,
            #[cfg(feature = "ble")]
            Inner::Ble(b) => Ok(b.subscribe(aid, iid).await?),
        }
    }

    /// Read several characteristics. Batched in one request on IP; a
    /// sequential loop on BLE (HAP-BLE has no batch PDU).
    ///
    /// # Errors
    ///
    /// IP: [`HapError::Transport`](crate::HapError::Transport)/[`HapError::Http`](crate::HapError::Http) on the request,
    /// [`HapError::Model`](crate::HapError::Model) if any entry fails to decode. BLE:
    /// [`HapError::Ble`](crate::HapError::Ble) from the first failing read.
    pub async fn read_many(&mut self, ids: &[(u64, u64)]) -> Result<Vec<((u64, u64), CharValue)>> {
        match &mut self.inner {
            Inner::Ip(h) => h.read_many(ids).await,
            #[cfg(feature = "ble")]
            Inner::Ble(b) => {
                let mut out = Vec::with_capacity(ids.len());
                for &(aid, iid) in ids {
                    out.push(((aid, iid), b.read(aid, iid).await?));
                }
                Ok(out)
            }
        }
    }

    /// Write several characteristics. Batched in one request on IP; a
    /// sequential loop on BLE (HAP-BLE has no batch PDU).
    ///
    /// # Errors
    ///
    /// IP: [`HapError::Transport`](crate::HapError::Transport)/[`HapError::Http`](crate::HapError::Http) on the request,
    /// [`HapError::Model`](crate::HapError::Model) on a per-characteristic failure. BLE:
    /// [`HapError::Ble`](crate::HapError::Ble) from the first failing write.
    pub async fn write_many(&mut self, writes: &[((u64, u64), CharValue)]) -> Result<()> {
        match &mut self.inner {
            Inner::Ip(h) => h.write_many(writes).await,
            #[cfg(feature = "ble")]
            Inner::Ble(b) => {
                for ((aid, iid), value) in writes {
                    b.write(*aid, *iid, value.clone()).await?;
                }
                Ok(())
            }
        }
    }

    /// An async stream of [`CharacteristicEvent`]s for every characteristic
    /// this handle has [`subscribe`](Self::subscribe)d to (IP), or armed via
    /// `subscribe`/broadcast/disconnected-event delivery (BLE).
    ///
    /// Multiple streams may be held at once; each is an independent
    /// broadcast receiver. Events that arrive while a particular stream is
    /// lagging are dropped for that stream.
    pub fn events(&self) -> impl Stream<Item = CharacteristicEvent> {
        let s: Pin<Box<dyn Stream<Item = CharacteristicEvent> + Send>> = match &self.inner {
            Inner::Ip(h) => Box::pin(h.events()),
            #[cfg(feature = "ble")]
            Inner::Ble(b) => Box::pin(b.events().map(|e| CharacteristicEvent {
                aid: e.aid,
                iid: e.iid,
                value: e.value,
            })),
        };
        s
    }

    /// A stream of [`ConnectionState`] transitions, for health reporting. On
    /// IP this reflects the reconnect supervisor; on BLE it never yields —
    /// sleepy links are intentionally fluid rather than reported as a single
    /// connected/disconnected state (see the crate docs).
    ///
    /// Each call returns an independent receiver; transitions that arrive
    /// while a particular stream is lagging are dropped for that stream.
    pub fn connection_state(&self) -> impl Stream<Item = ConnectionState> {
        let s: Pin<Box<dyn Stream<Item = ConnectionState> + Send>> = match &self.inner {
            Inner::Ip(h) => Box::pin(h.connection_state()),
            #[cfg(feature = "ble")]
            Inner::Ble(_) => Box::pin(tokio_stream::pending()),
        };
        s
    }

    /// Stop receiving change events for a characteristic. IP only.
    ///
    /// # Errors
    ///
    /// IP: [`HapError::Transport`](crate::HapError::Transport)/[`HapError::Http`](crate::HapError::Http) on the request,
    /// [`HapError::Model`](crate::HapError::Model) on a per-characteristic failure. BLE: always
    /// [`HapError::UnsupportedByTransport`](crate::HapError::UnsupportedByTransport) — HAP-BLE connected-event
    /// subscriptions are not individually revocable in this milestone.
    pub async fn unsubscribe(&mut self, aid: u64, iid: u64) -> Result<()> {
        match &mut self.inner {
            Inner::Ip(h) => h.unsubscribe(aid, iid).await,
            #[cfg(feature = "ble")]
            Inner::Ble(_) => Err(crate::error::HapError::UnsupportedByTransport(
                "unsubscribe",
            )),
        }
    }

    /// Timed write: reserve with `PUT /prepare {ttl,pid}` then write carrying
    /// that pid, completing within `ttl`. For security-sensitive accessories
    /// (locks). IP only.
    ///
    /// # Errors
    ///
    /// IP: [`HapError::Transport`](crate::HapError::Transport)/[`HapError::Http`](crate::HapError::Http) on either request,
    /// [`HapError::Model`](crate::HapError::Model) on a per-characteristic failure. BLE: always
    /// [`HapError::UnsupportedByTransport`](crate::HapError::UnsupportedByTransport) — HAP-BLE has no timed-write PDU.
    pub async fn write_timed(
        &mut self,
        aid: u64,
        iid: u64,
        value: CharValue,
        ttl: std::time::Duration,
    ) -> Result<()> {
        match &mut self.inner {
            Inner::Ip(h) => h.write_timed(aid, iid, value, ttl).await,
            #[cfg(feature = "ble")]
            Inner::Ble(_) => Err(crate::error::HapError::UnsupportedByTransport(
                "write_timed",
            )),
        }
    }

    /// Write requesting the post-write value back (the HAP `r` flag). IP
    /// only.
    ///
    /// The `r` flag is optional in HAP: accessories that don't support it
    /// reject the write with a per-characteristic status (surfaced as
    /// [`HapError::Model`](crate::HapError::Model)). Some shipping firmware (e.g. LIFX) declines it
    /// with status `-70405`.
    ///
    /// # Errors
    ///
    /// IP: [`HapError::Transport`](crate::HapError::Transport)/[`HapError::Http`](crate::HapError::Http) on the request,
    /// [`HapError::Model`](crate::HapError::Model) if the response cannot be decoded or the accessory
    /// rejects the read-response, [`HapError::CharacteristicNotFound`](crate::HapError::CharacteristicNotFound) if the
    /// accessory returns no value. BLE: always
    /// [`HapError::UnsupportedByTransport`](crate::HapError::UnsupportedByTransport) — HAP-BLE writes never return a
    /// value.
    pub async fn write_with_response(
        &mut self,
        aid: u64,
        iid: u64,
        value: CharValue,
    ) -> Result<CharValue> {
        match &mut self.inner {
            Inner::Ip(h) => h.write_with_response(aid, iid, value).await,
            #[cfg(feature = "ble")]
            Inner::Ble(_) => Err(crate::error::HapError::UnsupportedByTransport(
                "write_with_response",
            )),
        }
    }

    /// The current persistable broadcast state (key + latest GSN): BLE only,
    /// `None` on IP. Persist this so a later BLE reconnect can resume
    /// broadcast decryption — see [`crate::StoredBroadcast`].
    #[cfg(feature = "ble")]
    pub async fn broadcast_state(&self) -> Option<hap_ble::BleBroadcastState> {
        match &self.inner {
            Inner::Ip(_) => None,
            Inner::Ble(b) => Some(b.broadcast_state().await),
        }
    }

    /// The accessory's HAP pairing id: BLE only today, `None` on IP (the IP
    /// handle does not carry its id).
    #[must_use]
    pub fn pairing_id(&self) -> Option<&str> {
        match &self.inner {
            Inner::Ip(_) => None,
            #[cfg(feature = "ble")]
            Inner::Ble(b) => Some(b.pairing_id()),
        }
    }

    /// Enable encrypted broadcast notifications for the given characteristic
    /// instance ids. BLE only — call this while connected, before
    /// disconnecting, to receive sleepy-device events.
    ///
    /// # Errors
    ///
    /// BLE: propagates a session re-verify failure. IP: always
    /// [`HapError::UnsupportedByTransport`](crate::HapError::UnsupportedByTransport).
    #[cfg(feature = "ble")]
    pub async fn enable_broadcasts(&mut self, iids: &[u64]) -> Result<()> {
        match &mut self.inner {
            Inner::Ip(_) => Err(crate::error::HapError::UnsupportedByTransport(
                "enable_broadcasts",
            )),
            Inner::Ble(b) => Ok(b.enable_broadcasts(iids).await?),
        }
    }

    /// Watch disconnected-device (sleepy) events: regular-advertisement GSN
    /// bumps trigger a catch-up poll, and encrypted broadcast advertisements
    /// are decrypted directly. BLE only.
    ///
    /// # Errors
    ///
    /// BLE: [`HapError::Ble`](crate::HapError::Ble) if the advertisement source cannot start. IP:
    /// always [`HapError::UnsupportedByTransport`](crate::HapError::UnsupportedByTransport).
    #[cfg(feature = "ble")]
    pub async fn watch_sleepy_events(
        &mut self,
        advert_source: std::sync::Arc<dyn hap_ble::AdvertSource>,
        device_id: [u8; 6],
        poll_iids: Vec<(u64, u64)>,
    ) -> Result<()> {
        match &mut self.inner {
            Inner::Ip(_) => Err(crate::error::HapError::UnsupportedByTransport(
                "watch_sleepy_events",
            )),
            Inner::Ble(b) => Ok(b
                .watch_sleepy_events(advert_source, device_id, poll_iids)
                .await?),
        }
    }

    /// Escape hatch to the BLE-native handle, for anything not lifted onto
    /// this unified API. `None` on IP.
    #[cfg(feature = "ble")]
    pub fn as_ble(&mut self) -> Option<&mut hap_ble::BleAccessory> {
        match &mut self.inner {
            Inner::Ip(_) => None,
            Inner::Ble(b) => Some(b),
        }
    }
}
