//! Characteristic change events and the `EVENT/1.0` → [`Stream`] adapter.

use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

use hap_model::CharValue;

/// A single characteristic-changed notification pushed by an accessory.
///
/// Produced by [`AccessoryHandle::events`](crate::AccessoryHandle::events) for
/// every characteristic the handle has
/// [`subscribe`](crate::AccessoryHandle::subscribe)d to.
#[derive(Debug, Clone, PartialEq)]
pub struct CharacteristicEvent {
    /// Accessory id the event came from.
    pub aid: u64,
    /// Instance id of the changed characteristic.
    pub iid: u64,
    /// The new value.
    pub value: CharValue,
}

/// Wrap a broadcast receiver as a `Stream`, dropping any lagged messages rather
/// than surfacing the broadcast lag error to callers.
///
/// `BroadcastStream`'s item is `Result<T, BroadcastStreamRecvError>` — the error
/// only signals that a slow receiver lagged and skipped messages. Public stream
/// signatures want a bare `Stream<Item = T>`, so we drop lagged items with
/// `filter_map(Result::ok)`.
pub(crate) fn into_broadcast_stream<T: Clone + Send + 'static>(
    rx: broadcast::Receiver<T>,
) -> impl Stream<Item = T> {
    BroadcastStream::new(rx).filter_map(Result::ok)
}

/// Wrap a [`CharacteristicEvent`] broadcast receiver as a public `Stream`.
///
/// A thin alias over [`into_broadcast_stream`] for the `events()` call site.
pub(crate) fn into_stream(
    rx: broadcast::Receiver<CharacteristicEvent>,
) -> impl Stream<Item = CharacteristicEvent> {
    into_broadcast_stream(rx)
}
