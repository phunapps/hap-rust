//! Shared replay mock for the pairing orchestration tests.
//!
//! Compiled only under `#[cfg(test)]`. `Replay` implements the crate-internal
//! [`PairingConn`]/[`PairingSession`] seams so the loops can be driven against a
//! scripted request->response sequence with no socket. Tests live in-crate
//! (`src/{setup,verify,pairings}.rs`) because those seams are `pub(crate)`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::VecDeque;

use async_trait::async_trait;

use crate::error::Result;
use crate::wire::{PairingConn, PairingSession};

/// One scripted exchange.
pub(crate) struct Exchange {
    pub(crate) path: &'static str,
    /// If `Some`, the loop's outgoing request MUST equal these bytes. `None`
    /// skips the byte assertion (e.g. a Pair Verify M3 request, whose bytes
    /// depend on the uncommitted controller LTSK and so cannot be byte-matched).
    pub(crate) expect_request: Option<Vec<u8>>,
    pub(crate) response: Vec<u8>,
}

/// A mock that asserts each outgoing request against the next scripted exchange
/// and replays the recorded response.
pub(crate) struct Replay {
    script: VecDeque<Exchange>,
}

impl Replay {
    pub(crate) fn new(script: Vec<Exchange>) -> Self {
        Self {
            script: script.into(),
        }
    }
    pub(crate) fn is_drained(&self) -> bool {
        self.script.is_empty()
    }
    fn handle(&mut self, path: &str, body: &[u8]) -> Vec<u8> {
        let ex = self
            .script
            .pop_front()
            .expect("unexpected extra pairing request");
        assert_eq!(path, ex.path, "request path mismatch");
        if let Some(expected) = ex.expect_request {
            assert_eq!(body, expected.as_slice(), "request body mismatch");
        }
        ex.response
    }
}

#[async_trait]
impl PairingConn for Replay {
    async fn post_tlv8(&mut self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        Ok(self.handle(path, body))
    }
}

#[async_trait]
impl PairingSession for Replay {
    async fn post_tlv8(&mut self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        Ok(self.handle(path, body))
    }
}
