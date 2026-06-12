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

/// Wrap a broadcast receiver as a public `Stream` of events, dropping any
/// lagged messages rather than surfacing the broadcast lag error to callers.
///
/// `BroadcastStream`'s item is `Result<T, BroadcastStreamRecvError>` — the error
/// only signals that a slow receiver lagged and skipped messages. The canonical
/// `events()` signature is `Stream<Item = CharacteristicEvent>`, so we drop
/// lagged items with `filter_map(Result::ok)`.
pub(crate) fn into_stream(
    rx: broadcast::Receiver<CharacteristicEvent>,
) -> impl Stream<Item = CharacteristicEvent> {
    BroadcastStream::new(rx).filter_map(Result::ok)
}
