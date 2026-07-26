//! Coordination between the continuous advert scan and BLE connects. On macOS
//! CoreBluetooth a connect (and disconnect/wait-available) cannot complete
//! while a scan is running, so the connect path pauses the scan for its
//! duration: request the pause, wait for the scan task to actually drop its
//! scan stream, connect, then resume by dropping the guard.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// How long [`ScanGate::pause`] waits for the scan task to acknowledge that it
/// dropped its scan stream. A missing or wedged scan task must not block a
/// reconnect forever — after this the connect proceeds anyway (bounded by its
/// own connect timeout).
#[allow(dead_code)]
const PAUSE_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// The radio-ownership gate shared between the scan task and the connect path.
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct ScanGate {
    /// `true` while a connect owns the radio (the scan task must stop scanning).
    pause_tx: watch::Sender<bool>,
    /// `true` while the scan task holds a live scan stream.
    scanning_tx: watch::Sender<bool>,
    /// Serializes concurrent `pause` callers: a second connect must not resume
    /// the scan (its guard's drop) while the first is still connecting.
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl ScanGate {
    /// A fresh gate: nothing paused, nothing scanning.
    #[allow(dead_code)]
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            pause_tx: watch::channel(false).0,
            scanning_tx: watch::channel(false).0,
            lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Pause the scan for the lifetime of the returned guard: request the
    /// pause, then wait (bounded by [`PAUSE_ACK_TIMEOUT`]) until the scan task
    /// reports its scan stream dropped. Dropping the guard resumes the scan.
    #[allow(dead_code)]
    pub(crate) async fn pause(self: &Arc<Self>) -> ScanPauseGuard {
        let permit = Arc::clone(&self.lock).lock_owned().await;
        self.pause_tx.send_replace(true);
        let mut scanning = self.scanning_tx.subscribe();
        let _ = tokio::time::timeout(PAUSE_ACK_TIMEOUT, async {
            while *scanning.borrow_and_update() {
                if scanning.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
        ScanPauseGuard {
            gate: Arc::clone(self),
            _permit: permit,
        }
    }

    /// The scan task's view of pause requests: `true` means "drop your scan
    /// stream and hold off until this turns `false` again".
    #[allow(dead_code)]
    pub(crate) fn pause_watch(&self) -> watch::Receiver<bool> {
        self.pause_tx.subscribe()
    }

    /// The scan task reports whether it currently holds a live scan stream.
    #[allow(dead_code)]
    pub(crate) fn set_scanning(&self, scanning: bool) {
        self.scanning_tx.send_replace(scanning);
    }
}

/// Held while a connect owns the radio; dropping it resumes the scan.
#[allow(dead_code)]
pub(crate) struct ScanPauseGuard {
    gate: Arc<ScanGate>,
    _permit: tokio::sync::OwnedMutexGuard<()>,
}

impl Drop for ScanPauseGuard {
    fn drop(&mut self) {
        self.gate.pause_tx.send_replace(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `pause` waits until the scanner acknowledges (`scanning` -> false)
    /// before returning, and dropping the guard resumes (`pause` -> false).
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn pause_waits_for_scanner_ack_and_drop_resumes() {
        let gate = ScanGate::new();
        gate.set_scanning(true);

        // A stand-in scan task: on seeing pause=true, "drop the scan".
        let scanner_gate = gate.clone();
        let mut pause_rx = gate.pause_watch();
        let scanner = tokio::spawn(async move {
            while !*pause_rx.borrow_and_update() {
                if pause_rx.changed().await.is_err() {
                    return;
                }
            }
            scanner_gate.set_scanning(false);
        });

        let guard = gate.pause().await;
        // pause() must not have returned before the scanner acked.
        assert!(!*gate.scanning_tx.subscribe().borrow());
        scanner.await.unwrap();

        let mut pause_rx = gate.pause_watch();
        assert!(*pause_rx.borrow_and_update());
        drop(guard);
        assert!(!*pause_rx.borrow_and_update());
    }

    /// With no scanner running (`scanning` starts false), `pause` returns
    /// without consuming any (simulated) time.
    #[tokio::test(start_paused = true)]
    async fn pause_without_scanner_is_immediate() {
        let gate = ScanGate::new();
        let before = tokio::time::Instant::now();
        let _guard = gate.pause().await;
        assert_eq!(tokio::time::Instant::now(), before);
    }

    /// A scanner that never acks cannot wedge the connect path: `pause` gives
    /// up after `PAUSE_ACK_TIMEOUT` and lets the (itself timeout-bounded)
    /// connect proceed.
    #[tokio::test(start_paused = true)]
    async fn pause_times_out_on_wedged_scanner() {
        let gate = ScanGate::new();
        gate.set_scanning(true); // never acked
        let before = tokio::time::Instant::now();
        let _guard = gate.pause().await;
        assert!(tokio::time::Instant::now().duration_since(before) >= PAUSE_ACK_TIMEOUT);
    }

    /// Two concurrent pauses serialize: the second waits for the first guard's
    /// drop, so the scan cannot resume while either connect is in flight.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn concurrent_pauses_serialize() {
        let gate = ScanGate::new();
        let g1 = gate.pause().await;
        let gate2 = gate.clone();
        let second = tokio::spawn(async move {
            let _g2 = gate2.pause().await;
        });
        // On the current-thread test runtime the spawned task runs on yield and
        // must block on the gate's lock while g1 is held.
        tokio::task::yield_now().await;
        assert!(!second.is_finished());
        drop(g1);
        second.await.unwrap();
    }
}
