//! Cold-arm sleepy watch: arm an advert-driven watcher from a stored BLE
//! pairing with no blocking connect.
//!
//! [`watch_sleepy`](crate::HapController::watch_sleepy) validates the stored
//! record and returns a [`SleepyWatch`] immediately; a background task waits for
//! the device's next advertisement, connects once (serialized by a shared radio
//! mutex), enables broadcasts, disconnects so the sleepy device advertises
//! again, arms the self-sourcing sleepy watch, and pumps its events into the
//! watch's stream — auto-persisting each event's GSN via
//! [`PairingStore::save_broadcast_state`].

#![cfg(feature = "ble")]
use std::sync::Arc;

use hap_pairing::{PairingStore, StoredBroadcast};
use tokio::sync::{broadcast, Mutex};
use tokio_stream::{Stream, StreamExt as _};

use crate::event::{into_stream, CharacteristicEvent};

/// An advert-driven watch armed from a stored BLE pairing. Streams sleepy
/// events and auto-persists GSN/broadcast state. Stops on drop.
///
/// Created by [`HapController::watch_sleepy`](crate::HapController::watch_sleepy).
/// The watch returns immediately; the cold connect (which blocks until the
/// device next advertises) happens in a background task, so the caller is never
/// blocked on the radio. The armed accessory is owned here — dropping the watch
/// aborts its background tasks and releases the accessory.
pub struct SleepyWatch {
    events_tx: broadcast::Sender<CharacteristicEvent>,
    task: tokio::task::JoinHandle<()>,
    store: Arc<dyn PairingStore + Send + Sync>,
    accessory_id: String,
    /// The live accessory, populated once the background task has connected and
    /// armed it. `None` until then, so [`save_state`](Self::save_state) called
    /// before the connect completes is an `Ok` no-op.
    accessory: Arc<Mutex<Option<hap_ble::BleAccessory>>>,
}

impl std::fmt::Debug for SleepyWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SleepyWatch")
            .field("accessory_id", &self.accessory_id)
            .finish_non_exhaustive()
    }
}

impl Drop for SleepyWatch {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SleepyWatch {
    /// A stream of characteristic events from this sleepy watch.
    ///
    /// Each call returns a fresh subscriber; events published after the call are
    /// delivered.
    pub fn events(&self) -> impl Stream<Item = CharacteristicEvent> {
        into_stream(self.events_tx.subscribe())
    }

    /// Force-flush the latest broadcast/GSN state to the store.
    ///
    /// A no-op (returns `Ok`) if the background task has not yet connected the
    /// accessory; once connected, this writes the live broadcast material.
    ///
    /// # Errors
    /// [`crate::error::HapError::Pairing`] on store write failure.
    pub async fn save_state(&self) -> crate::error::Result<()> {
        let guard = self.accessory.lock().await;
        let Some(accessory) = guard.as_ref() else {
            return Ok(());
        };
        let state = accessory.broadcast_state().await;
        self.store
            .save_broadcast_state(
                &self.accessory_id,
                StoredBroadcast {
                    key: state.key,
                    gsn: state.gsn,
                },
            )
            .await?;
        Ok(())
    }

    /// Whether the background cold-arm task has finished (the device was
    /// connected and the watch armed, or the task ended/errored). A watch that
    /// is still waiting for the sleepy device to advertise is NOT finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// Cold-arm orchestration: spawn the background connect+arm+pump task and return
/// a [`SleepyWatch`] immediately, without awaiting the (blocking) connect.
///
/// The connect blocks until the sleepy device next advertises, so it MUST run
/// inside the spawned task — never before this function returns.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_watch(
    connector: Arc<dyn hap_ble::SleepyConnector>,
    store: Arc<dyn PairingStore + Send + Sync>,
    radio_lock: Arc<Mutex<()>>,
    accessory_id: String,
    pairing: hap_crypto::AccessoryPairing,
    device_id: [u8; 6],
    broadcast: Option<StoredBroadcast>,
    poll_iids: Vec<(u64, u64)>,
) -> SleepyWatch {
    let (events_tx, _) = broadcast::channel(64);
    let accessory: Arc<Mutex<Option<hap_ble::BleAccessory>>> = Arc::new(Mutex::new(None));

    let task = tokio::spawn({
        let events_tx = events_tx.clone();
        let store = store.clone();
        let accessory = accessory.clone();
        let accessory_id = accessory_id.clone();
        async move {
            let bstate = broadcast.map(|b| hap_ble::BleBroadcastState {
                key: b.key,
                gsn: b.gsn,
            });
            let poll_iid_list: Vec<u64> = poll_iids.iter().map(|(_, iid)| *iid).collect();
            // Everything that drives the radio — the (blocking) cold connect, the
            // broadcast-enable writes, the disconnect, and the arm of the advert
            // watch — is serialized against other sleepy watches by the shared
            // radio mutex. The guard is released before the (long-lived) event
            // pump so other watches can connect. `src` is subscribed before the
            // arm so an event produced during/just after arming is not missed
            // (the stream owns a broadcast receiver, so it does not borrow `acc`).
            let (acc, mut src) = {
                let _radio = radio_lock.lock().await;
                let Ok(mut acc) = connector.connect(device_id, &pairing, bstate).await else {
                    return;
                };
                // Request the accessory start encrypted (0x11) broadcasts for the
                // watched characteristics, so it advertises value changes while
                // we are disconnected. Best-effort: a failure must not abort the
                // watch, and the disconnected-event (0x06) path works without it.
                let _ = acc.enable_broadcasts(&poll_iid_list).await;
                // Drop the link so the sleepy device advertises again.
                acc.disconnect().await;
                // Subscribe before arming so an event produced during/just after
                // arming is not missed.
                let src = acc.events();
                if acc.watch_sleepy_events(poll_iids).await.is_err() {
                    return;
                }
                (acc, src)
            };
            // Publish the live, armed accessory so `save_state` can flush it.
            *accessory.lock().await = Some(acc);

            while let Some(ev) = src.next().await {
                let _ = events_tx.send(CharacteristicEvent {
                    aid: ev.aid,
                    iid: ev.iid,
                    value: ev.value,
                });
                // Auto-persist the new GSN/broadcast material after each event.
                let state = {
                    let guard = accessory.lock().await;
                    match guard.as_ref() {
                        Some(acc) => acc.broadcast_state().await,
                        None => continue,
                    }
                };
                let _ = store
                    .save_broadcast_state(
                        &accessory_id,
                        StoredBroadcast {
                            key: state.key,
                            gsn: state.gsn,
                        },
                    )
                    .await;
            }
        }
    });

    SleepyWatch {
        events_tx,
        task,
        store,
        accessory_id,
        accessory,
    }
}
