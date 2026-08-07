//! The Thread controller entry point: identity, pair, and connect over CoAP.

use std::net::SocketAddr;
use std::sync::Arc;

use hap_crypto::{AccessoryPairing, ControllerKeypair};

use crate::accessory::{SecureCoapConnection, ThreadAccessory};
use crate::coap::{CoapTransport, UdpCoapTransport, PATH_IDENTIFY};
use crate::error::Result;
use crate::pairing;
use crate::session::CoapSession;

/// A HAP-over-Thread controller: holds the long-term controller identity used
/// for pairing and Pair Verify, and drives pairing/connection over CoAP.
pub struct ThreadController {
    keypair: ControllerKeypair,
}

impl ThreadController {
    /// Create a controller from an existing long-term identity.
    pub fn new(keypair: ControllerKeypair) -> Self {
        Self { keypair }
    }

    /// Generate a fresh controller identity with the given pairing id.
    pub fn generate(id: String) -> Self {
        Self {
            keypair: ControllerKeypair::generate(id),
        }
    }

    /// The controller's pairing identity.
    pub fn keypair(&self) -> &ControllerKeypair {
        &self.keypair
    }

    /// Ask the (unpaired or paired) accessory at `addr` to identify itself
    /// (e.g. blink or beep) — an unauthenticated POST to the identify resource.
    ///
    /// # Errors
    /// Transport and CoAP-code failures.
    pub async fn identify(&self, addr: SocketAddr) -> Result<()> {
        let transport = UdpCoapTransport::connect(addr).await?;
        transport
            .post(PATH_IDENTIFY, &[])
            .await?
            .changed_payload()?;
        Ok(())
    }

    /// Pair with an accessory at `addr` (its `[ipv6]:port` CoAP endpoint) using
    /// its 8-digit setup code, returning the connected [`ThreadAccessory`] and
    /// the [`AccessoryPairing`] to persist.
    ///
    /// # Errors
    /// Transport, CoAP, and pairing-crypto failures.
    pub async fn pair(
        &self,
        addr: SocketAddr,
        setup_code: &str,
    ) -> Result<(ThreadAccessory, AccessoryPairing)> {
        let transport = Arc::new(UdpCoapTransport::connect(addr).await?);
        self.pair_with_transport(transport, setup_code).await
    }

    /// Connect to an already-paired accessory at `addr` via Pair Verify.
    ///
    /// # Errors
    /// Transport, CoAP, and verify failures ([`crate::ThreadError::SessionExpired`]
    /// if the accessory has forgotten the pairing).
    pub async fn connect(
        &self,
        addr: SocketAddr,
        pairing: &AccessoryPairing,
    ) -> Result<ThreadAccessory> {
        let transport = Arc::new(UdpCoapTransport::connect(addr).await?);
        self.connect_with_transport(transport, pairing).await
    }

    /// Pair over an arbitrary transport (the seam mock/loopback tests use).
    pub(crate) async fn pair_with_transport(
        &self,
        transport: Arc<dyn CoapTransport>,
        setup_code: &str,
    ) -> Result<(ThreadAccessory, AccessoryPairing)> {
        let pairing =
            pairing::pair_setup(transport.as_ref(), setup_code, self.keypair.clone()).await?;
        let accessory = self.verify_and_connect(transport, &pairing).await?;
        Ok((accessory, pairing))
    }

    /// Connect over an arbitrary transport.
    pub(crate) async fn connect_with_transport(
        &self,
        transport: Arc<dyn CoapTransport>,
        pairing: &AccessoryPairing,
    ) -> Result<ThreadAccessory> {
        self.verify_and_connect(transport, pairing).await
    }

    async fn verify_and_connect(
        &self,
        transport: Arc<dyn CoapTransport>,
        pairing: &AccessoryPairing,
    ) -> Result<ThreadAccessory> {
        let (keys, event_key) =
            pairing::pair_verify(transport.as_ref(), &self.keypair, pairing).await?;
        let session = CoapSession::new(&keys, event_key);
        let conn = SecureCoapConnection::new(transport, session);
        Ok(ThreadAccessory::new(conn))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::coap::{CoapResponse, MockCoapTransport};
    use crate::error::ThreadError;

    #[tokio::test]
    async fn connect_surfaces_session_expired_on_not_found() {
        let mock = Arc::new(MockCoapTransport::new());
        mock.queue(CoapResponse {
            code: (4, 4),
            payload: vec![],
        });
        let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());
        let pairing = AccessoryPairing {
            pairing_id: "11:22:33:44:55:66".into(),
            ltpk: controller.keypair().ltpk(),
        };
        let err = controller
            .connect_with_transport(mock.clone(), &pairing)
            .await;
        assert!(matches!(err, Err(ThreadError::SessionExpired)));
        // Pair Verify M1 was posted to the verify resource `/2`.
        assert_eq!(mock.requests()[0].0, "2");
    }
}
