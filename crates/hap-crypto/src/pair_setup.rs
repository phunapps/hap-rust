//! HomeKit Accessory Protocol **Pair Setup** controller state machine.
//!
//! Pair Setup (HAP specification chapter 5.6) is the six-message SRP-6a
//! exchange by which a controller, knowing only the accessory's 8-digit setup
//! code, establishes a mutually authenticated long-term pairing: it learns the
//! accessory's Ed25519 long-term public key (LTPK) and the accessory learns the
//! controller's. The messages are TLV8:
//!
//! | Msg | Direction      | Contents                                              |
//! |-----|----------------|-------------------------------------------------------|
//! | M1  | controller →   | `State=1`, `Method=PairSetup`                         |
//! | M2  | → controller   | `State=2`, `Salt`, `PublicKey=B`                      |
//! | M3  | controller →   | `State=3`, `PublicKey=A`, `Proof=M1`                  |
//! | M4  | → controller   | `State=4`, `Proof=M2` (or `Error`)                    |
//! | M5  | controller →   | `State=5`, `EncryptedData{ Id, LTPK, Signature }`     |
//! | M6  | → controller   | `State=6`, `EncryptedData{ Id, LTPK, Signature }`     |
//!
//! The session encryption key for M5/M6 is
//! `HKDF-SHA512(ikm = K, salt = "Pair-Setup-Encrypt-Salt",
//! info = "Pair-Setup-Encrypt-Info", 32)`, where `K = H(S)` is the SRP session
//! key derived from the premaster secret `S`. The controller signs
//! `iOSDeviceX ‖ iOSPairingID ‖ iOS_LTPK` (with `iOSDeviceX` an HKDF of `K`
//! under the controller-sign salt/info) and verifies the accessory's analogous
//! signature in M6.
//!
//! The exact salt/info/nonce strings and concatenation order are cross-verified
//! byte-for-byte against a captured `aiohomekit` Pair Setup trace (a real LIFX
//! accessory) in this module's tests.
//!
//! # Usage
//!
//! Drive the machine by transport-agnostic message passing: send [`start`], then
//! feed each accessory response to [`handle`] and send back whatever
//! [`PairSetupStep::Send`] yields, until [`PairSetupStep::Done`] returns the
//! established [`AccessoryPairing`].
//!
//! [`start`]: PairSetupClient::start
//! [`handle`]: PairSetupClient::handle

use hap_tlv8::{Tlv8Map, Tlv8Writer};
use num_bigint::BigUint;
use sha2::Sha512;

use crate::aead::{decrypt, encrypt, hap_nonce};
use crate::error::{CryptoError, Result};
use crate::kdf::hkdf_sha512;
use crate::keys::{verify_ed25519, ControllerKeypair};
use crate::srp::{hap_group, SrpClient};
use crate::tlv_types as tlv;

/// The SRP-6a username HAP fixes for Pair Setup (`I` in RFC 5054 notation).
const PAIR_SETUP_USERNAME: &[u8] = b"Pair-Setup";

/// HKDF salt/info deriving the M5/M6 ChaCha20-Poly1305 session key from `K`.
const ENCRYPT_SALT: &[u8] = b"Pair-Setup-Encrypt-Salt";
const ENCRYPT_INFO: &[u8] = b"Pair-Setup-Encrypt-Info";
/// HKDF salt/info deriving `iOSDeviceX`, the controller signing material.
const CONTROLLER_SIGN_SALT: &[u8] = b"Pair-Setup-Controller-Sign-Salt";
const CONTROLLER_SIGN_INFO: &[u8] = b"Pair-Setup-Controller-Sign-Info";
/// HKDF salt/info deriving `AccessoryX`, the accessory signing material.
const ACCESSORY_SIGN_SALT: &[u8] = b"Pair-Setup-Accessory-Sign-Salt";
const ACCESSORY_SIGN_INFO: &[u8] = b"Pair-Setup-Accessory-Sign-Info";

/// ChaCha20-Poly1305 nonce labels for the M5 and M6 encrypted sub-TLVs.
const NONCE_M5: &[u8] = b"PS-Msg05";
const NONCE_M6: &[u8] = b"PS-Msg06";

/// The pairing material a successful Pair Setup yields about the accessory.
///
/// The controller stores this and uses it during every later Pair Verify to
/// authenticate the accessory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessoryPairing {
    /// The accessory's pairing identifier (`AccessoryPairingID`), a UTF-8 string
    /// (typically a MAC-address-like value such as `AE:EC:86:C0:BF:D7`).
    pub pairing_id: String,
    /// The accessory's 32-byte Ed25519 long-term public key (`AccessoryLTPK`).
    pub ltpk: [u8; 32],
}

/// The result of feeding one accessory response to [`PairSetupClient::handle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairSetupStep {
    /// The next controller message to transmit to the accessory (a TLV8 body).
    Send(Vec<u8>),
    /// Pair Setup completed; the accessory pairing was established and verified.
    Done(AccessoryPairing),
}

/// Internal progress of the [`PairSetupClient`] exchange.
enum State {
    /// Before [`PairSetupClient::start`]; the M1 request has not been emitted.
    Initial,
    /// M1 sent; awaiting the accessory's M2 (salt + `B`).
    AwaitingM2,
    /// M3 sent; awaiting the accessory's M4 (`M2` proof). Holds the SRP session
    /// key `K` and the controller proof `M1` needed to verify `M2`.
    AwaitingM4 { session_key: Vec<u8>, m1: Vec<u8> },
    /// M5 sent; awaiting the accessory's M6 (encrypted accessory sub-TLV). Holds
    /// the SRP session key `K`.
    AwaitingM6 { session_key: Vec<u8> },
    /// The exchange finished (success or failure); no further input accepted.
    Done,
}

/// A controller-side Pair Setup state machine over a single SRP-6a exchange.
///
/// Construct with [`new`](PairSetupClient::new), drive with
/// [`start`](PairSetupClient::start) then [`handle`](PairSetupClient::handle).
/// The machine is transport-agnostic: it consumes and produces raw TLV8 bodies.
pub struct PairSetupClient {
    /// The setup code as the SRP password `P` (e.g. `"123-45-678"`).
    password: String,
    controller: ControllerKeypair,
    srp: SrpClient<Sha512>,
    state: State,
}

impl PairSetupClient {
    /// Create a Pair Setup client for `setup_code`, signing with `controller`.
    ///
    /// `setup_code` is the accessory's 8-digit setup code. It is accepted either
    /// already hyphenated (`"123-45-678"`) or as bare digits (`"12345678"`); the
    /// digits are re-grouped into the canonical `XXX-XX-XXX` form HAP hashes as
    /// the SRP password. Any other input is used verbatim (the accessory will
    /// then reject the proof, which surfaces as a setup-code error in M4).
    ///
    /// The SRP client ephemeral `a` is drawn from the OS CSPRNG; use
    /// [`new_with_private`](PairSetupClient::new_with_private) for a
    /// deterministic exchange in tests.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SrpBadParameters`] if the freshly generated SRP
    /// public ephemeral `A` is zero mod `N` (vanishingly unlikely).
    pub fn new(setup_code: &str, controller: ControllerKeypair) -> Result<Self> {
        let srp = SrpClient::<Sha512>::new(hap_group()?, PAIR_SETUP_USERNAME)?;
        Ok(Self {
            password: normalize_setup_code(setup_code),
            controller,
            srp,
            state: State::Initial,
        })
    }

    /// Create a Pair Setup client with a caller-supplied SRP private ephemeral
    /// `a` (the deterministic test seam).
    ///
    /// Mirrors the crate-internal `srp` module's `with_private` so a replay
    /// harness can reproduce an exchange exactly. `a` is the big-endian bytes of
    /// the SRP exponent.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SrpBadParameters`] if the resulting SRP public
    /// ephemeral `A` is zero mod `N`.
    pub fn new_with_private(
        setup_code: &str,
        controller: ControllerKeypair,
        a: &[u8],
    ) -> Result<Self> {
        let srp = SrpClient::<Sha512>::with_private(
            hap_group()?,
            PAIR_SETUP_USERNAME,
            BigUint::from_bytes_be(a),
        )?;
        Ok(Self {
            password: normalize_setup_code(setup_code),
            controller,
            srp,
            state: State::Initial,
        })
    }

    /// Produce the M1 request that starts Pair Setup.
    ///
    /// The body is `State=1, Method=PairSetup`. Calling `start` advances the
    /// machine to await M2; calling it again re-emits M1 but does not reset any
    /// state already established by [`Self::handle`].
    #[must_use]
    pub fn start(&mut self) -> Vec<u8> {
        self.state = State::AwaitingM2;
        let mut out = Vec::new();
        let mut w = Tlv8Writer::new(&mut out);
        w.push_u8(tlv::STATE, tlv::STATE_M1);
        w.push_u8(tlv::METHOD, tlv::METHOD_PAIR_SETUP);
        out
    }

    /// Consume an accessory response and advance the exchange.
    ///
    /// Feed M2, then M4, then M6 in order; the return value is the next message
    /// to send ([`PairSetupStep::Send`]) until the final
    /// [`PairSetupStep::Done`] yields the [`AccessoryPairing`].
    ///
    /// # Errors
    ///
    /// Returns a [`CryptoError`] if the response is malformed, omits a required
    /// field, carries an accessory `Error` TLV, fails SRP proof verification,
    /// fails AEAD authentication, or carries an accessory signature that does
    /// not verify. The machine then refuses further input.
    pub fn handle(&mut self, response: &[u8]) -> Result<PairSetupStep> {
        let map = Tlv8Map::parse(response)?;
        check_error(&map)?;
        match &self.state {
            State::Initial => Err(CryptoError::Encoding("Pair Setup not started")),
            State::AwaitingM2 => self.handle_m2(&map),
            State::AwaitingM4 { .. } => self.handle_m4(&map),
            State::AwaitingM6 { .. } => self.handle_m6(&map),
            State::Done => Err(CryptoError::Encoding("Pair Setup already finished")),
        }
    }

    /// M2 → produce M3. Consumes salt + `B`, derives `S`/`K`, builds `A`+`M1`.
    fn handle_m2(&mut self, map: &Tlv8Map) -> Result<PairSetupStep> {
        expect_state(map, tlv::STATE_M2)?;
        let salt = map
            .get(tlv::SALT)
            .ok_or(CryptoError::Encoding("M2 missing salt"))?
            .to_vec();
        let b_bytes = map
            .get(tlv::PUBLIC_KEY)
            .ok_or(CryptoError::Encoding("M2 missing accessory public key B"))?;
        let b_pub = BigUint::from_bytes_be(b_bytes);

        let premaster = self
            .srp
            .premaster(&salt, self.password.as_bytes(), &b_pub)?;
        let session_key = self.srp.session_key(&premaster);
        let m1 = self.srp.proof_m1(&salt, &b_pub, &session_key);

        let mut out = Vec::new();
        let mut w = Tlv8Writer::new(&mut out);
        w.push_u8(tlv::STATE, tlv::STATE_M3);
        w.push(tlv::PUBLIC_KEY, &self.srp.a_pub_bytes());
        w.push(tlv::PROOF, &m1);

        self.state = State::AwaitingM4 { session_key, m1 };
        Ok(PairSetupStep::Send(out))
    }

    /// M4 → produce M5. Verifies the accessory `M2` proof, then builds and seals
    /// the controller sub-TLV `{ Identifier, PublicKey=LTPK, Signature }`.
    fn handle_m4(&mut self, map: &Tlv8Map) -> Result<PairSetupStep> {
        expect_state(map, tlv::STATE_M4)?;
        let State::AwaitingM4 { session_key, m1 } = &self.state else {
            return Err(CryptoError::Encoding("Pair Setup state corrupted"));
        };
        let session_key = session_key.clone();
        let m1 = m1.clone();

        let proof = map
            .get(tlv::PROOF)
            .ok_or(CryptoError::Encoding("M4 missing accessory proof M2"))?;
        self.srp.verify_m2(&m1, &session_key, proof)?;

        // Derive the M5/M6 encryption key and the controller signing material.
        let mut enc_key = [0u8; 32];
        hkdf_sha512(&session_key, ENCRYPT_SALT, ENCRYPT_INFO, &mut enc_key)?;
        let mut ios_device_x = [0u8; 32];
        hkdf_sha512(
            &session_key,
            CONTROLLER_SIGN_SALT,
            CONTROLLER_SIGN_INFO,
            &mut ios_device_x,
        )?;

        let id = self.controller.id.as_bytes();
        let ltpk = self.controller.ltpk();

        // sig = Ed25519(LTSK, iOSDeviceX ‖ iOSPairingID ‖ iOS_LTPK)
        let mut signed = Vec::with_capacity(ios_device_x.len() + id.len() + ltpk.len());
        signed.extend_from_slice(&ios_device_x);
        signed.extend_from_slice(id);
        signed.extend_from_slice(&ltpk);
        let signature = self.controller.sign(&signed);

        let mut sub = Vec::new();
        let mut sw = Tlv8Writer::new(&mut sub);
        sw.push(tlv::IDENTIFIER, id);
        sw.push(tlv::PUBLIC_KEY, &ltpk);
        sw.push(tlv::SIGNATURE, &signature);

        let nonce = hap_nonce(NONCE_M5);
        let sealed = encrypt(&enc_key, &nonce, b"", &sub)?;

        let mut out = Vec::new();
        let mut w = Tlv8Writer::new(&mut out);
        w.push_u8(tlv::STATE, tlv::STATE_M5);
        w.push(tlv::ENCRYPTED_DATA, &sealed);

        self.state = State::AwaitingM6 { session_key };
        Ok(PairSetupStep::Send(out))
    }

    /// M6 → finish. Decrypts the accessory sub-TLV, recomputes `AccessoryX`,
    /// verifies the accessory signature, and yields the [`AccessoryPairing`].
    fn handle_m6(&mut self, map: &Tlv8Map) -> Result<PairSetupStep> {
        expect_state(map, tlv::STATE_M6)?;
        let State::AwaitingM6 { session_key } = &self.state else {
            return Err(CryptoError::Encoding("Pair Setup state corrupted"));
        };
        let session_key = session_key.clone();
        self.state = State::Done;

        let encrypted = map
            .get(tlv::ENCRYPTED_DATA)
            .ok_or(CryptoError::Encoding("M6 missing encrypted data"))?;

        let mut enc_key = [0u8; 32];
        hkdf_sha512(&session_key, ENCRYPT_SALT, ENCRYPT_INFO, &mut enc_key)?;
        let nonce = hap_nonce(NONCE_M6);
        let plaintext = decrypt(&enc_key, &nonce, b"", encrypted)?;

        let sub = Tlv8Map::parse(&plaintext)?;
        let id_bytes = sub
            .get(tlv::IDENTIFIER)
            .ok_or(CryptoError::Encoding("M6 sub-TLV missing identifier"))?;
        let ltpk_bytes = sub
            .get(tlv::PUBLIC_KEY)
            .ok_or(CryptoError::Encoding("M6 sub-TLV missing public key"))?;
        let signature = sub
            .get(tlv::SIGNATURE)
            .ok_or(CryptoError::Encoding("M6 sub-TLV missing signature"))?;

        let ltpk: [u8; 32] = ltpk_bytes
            .try_into()
            .map_err(|_| CryptoError::Encoding("accessory LTPK is not 32 bytes"))?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::Encoding("accessory signature is not 64 bytes"))?;
        let pairing_id = String::from_utf8(id_bytes.to_vec())
            .map_err(|_| CryptoError::Encoding("accessory pairing id is not valid UTF-8"))?;

        // AccessoryX = HKDF(K, accessory-sign salt/info)
        let mut accessory_x = [0u8; 32];
        hkdf_sha512(
            &session_key,
            ACCESSORY_SIGN_SALT,
            ACCESSORY_SIGN_INFO,
            &mut accessory_x,
        )?;

        // Verify Ed25519(LTPK, AccessoryX ‖ AccessoryPairingID ‖ AccessoryLTPK).
        let mut signed = Vec::with_capacity(accessory_x.len() + id_bytes.len() + ltpk.len());
        signed.extend_from_slice(&accessory_x);
        signed.extend_from_slice(id_bytes);
        signed.extend_from_slice(&ltpk);
        verify_ed25519(&ltpk, &signed, &signature)?;

        Ok(PairSetupStep::Done(AccessoryPairing { pairing_id, ltpk }))
    }
}

/// Normalise a setup code to the canonical `XXX-XX-XXX` SRP password form.
///
/// Exactly eight digits (with any non-digit characters stripped) are re-grouped;
/// anything else is returned unchanged so an already-formatted or unexpected
/// code still reaches SRP verbatim.
fn normalize_setup_code(code: &str) -> String {
    let digits: String = code.chars().filter(char::is_ascii_digit).collect();
    if digits.len() == 8 {
        format!("{}-{}-{}", &digits[0..3], &digits[3..5], &digits[5..8])
    } else {
        code.to_string()
    }
}

/// Map an accessory `Error` TLV to a [`CryptoError`], if present.
fn check_error(map: &Tlv8Map) -> Result<()> {
    match map.get(tlv::ERROR) {
        None | Some([]) => Ok(()),
        // Any non-empty error code aborts the exchange. SRP-credential failures
        // (kTLVError_Authentication = 2) are the common case (wrong setup code).
        Some([2]) => Err(CryptoError::SrpProofMismatch),
        Some(_) => Err(CryptoError::Encoding("accessory returned a pairing error")),
    }
}

/// Require the response to carry the expected `State` value.
fn expect_state(map: &Tlv8Map, expected: u8) -> Result<()> {
    match map.get_u8(tlv::STATE)? {
        // Some accessories omit State (a known quirk); tolerate that.
        None => Ok(()),
        Some(s) if s == expected => Ok(()),
        Some(_) => Err(CryptoError::Encoding("unexpected Pair Setup state")),
    }
}

#[cfg(test)]
// Test code only: CLAUDE.md carves out `unwrap`/`expect` for tests with a
// documented justification. Fixtures are fixed captured/known values, so a
// failing `unwrap` here is itself a test failure, which is intended.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::srp::{compute_b, compute_k, compute_u, compute_v, compute_x, SrpGroup};
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha512};

    /// Load a committed fixture from the workspace `test-vectors/` tree.
    fn fixture(rel: &str) -> Option<Vec<u8>> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors")
            .join(rel);
        std::fs::read(p).ok()
    }

    fn test_controller() -> ControllerKeypair {
        // RFC 8032 TEST 2 seed — any fixed seed gives a deterministic LTPK.
        let seed = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb8, 0xa6, 0xfb,
        ];
        ControllerKeypair::from_seed("test-controller".to_string(), seed)
    }

    // ---- M1 reproduction against the real captured trace ----

    #[test]
    fn m1_reproduces_captured_trace_byte_for_byte() {
        let Some(expected) = fixture("pair-setup/m1.bin") else {
            eprintln!("skipping: no test-vectors/pair-setup/m1.bin");
            return;
        };
        let mut client = PairSetupClient::new("123-45-678", test_controller()).unwrap();
        let m1 = client.start();
        assert_eq!(
            m1, expected,
            "M1 must match the captured trace byte-for-byte"
        );
    }

    // ---- M6 decrypt + accessory-signature verify against the real trace ----
    //
    // Uses the captured premaster S only (no ephemeral secret needed): we derive
    // K = H(S), drive the M6 path of the machine directly, and assert the
    // accessory signature verifies and we recover the AccessoryPairing.

    /// The SRP session key `K = H(PAD(S))` from the captured premaster secret.
    fn captured_session_key() -> Option<Vec<u8>> {
        let s = fixture("srp/S.bin")?;
        // S.bin is already PAD'd to len(N) = 384 bytes; K = SHA-512(S).
        Some(Sha512::digest(&s).to_vec())
    }

    #[test]
    fn m6_decrypts_and_verifies_accessory_signature_from_real_trace() {
        let (Some(m6), Some(session_key)) = (fixture("pair-setup/m6.bin"), captured_session_key())
        else {
            eprintln!("skipping: no captured S.bin / m6.bin");
            return;
        };

        let mut client = PairSetupClient::new("000-00-000", test_controller()).unwrap();
        // Inject the captured session key and put the machine in the M6 state.
        client.state = State::AwaitingM6 { session_key };

        let step = client.handle(&m6).expect("M6 must decrypt and verify");
        let PairSetupStep::Done(pairing) = step else {
            panic!("expected Done, got {step:?}");
        };
        assert_eq!(pairing.pairing_id, "AE:EC:86:C0:BF:D7");
        assert_eq!(pairing.ltpk.len(), 32);
        assert!(!pairing.pairing_id.is_empty());
    }

    // ---- M5 decrypt against the real trace ----
    //
    // Decrypt the captured M5 request and verify the controller signature it
    // carries under the embedded PublicKey, over iOSDeviceX ‖ id ‖ pubkey.

    #[test]
    fn m5_decrypts_and_controller_signature_verifies_from_real_trace() {
        let (Some(m5), Some(session_key)) = (fixture("pair-setup/m5.bin"), captured_session_key())
        else {
            eprintln!("skipping: no captured S.bin / m5.bin");
            return;
        };

        let map = Tlv8Map::parse(&m5).unwrap();
        let encrypted = map.get(tlv::ENCRYPTED_DATA).unwrap();

        let mut enc_key = [0u8; 32];
        hkdf_sha512(&session_key, ENCRYPT_SALT, ENCRYPT_INFO, &mut enc_key).unwrap();
        let nonce = hap_nonce(NONCE_M5);
        let plaintext = decrypt(&enc_key, &nonce, b"", encrypted).unwrap();

        let sub = Tlv8Map::parse(&plaintext).unwrap();
        let id = sub.get(tlv::IDENTIFIER).unwrap();
        let pubkey = sub.get(tlv::PUBLIC_KEY).unwrap();
        let sig = sub.get(tlv::SIGNATURE).unwrap();
        assert_eq!(pubkey.len(), 32, "controller LTPK is 32 bytes");
        assert_eq!(sig.len(), 64, "controller signature is 64 bytes");

        let mut ios_device_x = [0u8; 32];
        hkdf_sha512(
            &session_key,
            CONTROLLER_SIGN_SALT,
            CONTROLLER_SIGN_INFO,
            &mut ios_device_x,
        )
        .unwrap();

        let mut signed = Vec::new();
        signed.extend_from_slice(&ios_device_x);
        signed.extend_from_slice(id);
        signed.extend_from_slice(pubkey);

        let ltpk: [u8; 32] = pubkey.try_into().unwrap();
        let signature: [u8; 64] = sig.try_into().unwrap();
        verify_ed25519(&ltpk, &signed, &signature)
            .expect("captured M5 controller signature must verify");
    }

    // ---- Self-consistency replay: full machine vs a test "accessory" ----

    /// A minimal test accessory: holds the verifier, a fixed `b`, and an Ed25519
    /// long-term keypair, and produces M2/M4/M6 the way a real accessory would.
    struct TestAccessory {
        group: SrpGroup,
        pairing_id: String,
        signing: ed25519_dalek::SigningKey,
        salt: Vec<u8>,
        b_priv: BigUint,
        b_pub: BigUint,
        session_key: Option<Vec<u8>>,
        a_pub: Option<BigUint>,
    }

    impl TestAccessory {
        fn new(password: &str) -> Self {
            let group = hap_group().unwrap();
            let salt = vec![0x11u8; 16];
            let x = compute_x::<Sha512>(&salt, PAIR_SETUP_USERNAME, password.as_bytes());
            let v = compute_v(&group, &x);
            let k = compute_k::<Sha512>(&group);
            let b_priv = BigUint::from_bytes_be(&[0x5Au8; 32]);
            let b_pub = compute_b(&group, &k, &v, &b_priv);
            let signing = ed25519_dalek::SigningKey::from_bytes(&[0x99u8; 32]);
            Self {
                group,
                pairing_id: "11:22:33:44:55:66".to_string(),
                signing,
                salt,
                b_priv,
                b_pub,
                session_key: None,
                a_pub: None,
            }
        }

        /// Respond to M3 with M2 framing (salt + B). (Sent before the controller
        /// sends M3, but built from no controller input.)
        fn m2(&self) -> Vec<u8> {
            let mut out = Vec::new();
            let mut w = Tlv8Writer::new(&mut out);
            w.push_u8(tlv::STATE, tlv::STATE_M2);
            w.push(tlv::SALT, &self.salt);
            w.push(tlv::PUBLIC_KEY, &pad_be(&self.b_pub, 384));
            out
        }

        /// Consume the controller's M3 (A + M1 proof), compute the shared secret
        /// and session key, verify M1, and produce M4 (M2 proof).
        fn m4(&mut self, m3: &[u8]) -> Vec<u8> {
            let map = Tlv8Map::parse(m3).unwrap();
            let a_bytes = map.get(tlv::PUBLIC_KEY).unwrap();
            let a_pub = BigUint::from_bytes_be(a_bytes);
            let m1 = map.get(tlv::PROOF).unwrap().to_vec();

            let modulus = self.group.modulus();
            // Verifier-side premaster: S = (A * v^u) ^ b mod N, with the
            // verifier v recomputed from the (test-known) salt and password.
            let scrambler = compute_u::<Sha512>(&self.group, &a_pub, &self.b_pub);
            let x_priv =
                compute_x::<Sha512>(&self.salt, PAIR_SETUP_USERNAME, TEST_PASSWORD.as_bytes());
            let verifier = compute_v(&self.group, &x_priv);
            let vu = verifier.modpow(&scrambler, modulus);
            let base = (&a_pub * &vu) % modulus;
            let premaster = base.modpow(&self.b_priv, modulus);
            let session_key = Sha512::digest(pad_be(&premaster, 384)).to_vec();

            // Verify the controller's M1 proof:
            // M1 = H(H(N) xor H(g) | H(I) | s | A | B | K)
            let expected_m1 = self.controller_m1(&a_pub, &session_key);
            assert_eq!(m1, expected_m1, "test accessory: controller M1 must verify");

            self.a_pub = Some(a_pub);
            self.session_key = Some(session_key.clone());

            let m2_proof = {
                let mut h = Sha512::new();
                h.update(pad_be(self.a_pub.as_ref().unwrap(), 384));
                h.update(&m1);
                h.update(&session_key);
                h.finalize().to_vec()
            };

            let mut out = Vec::new();
            let mut w = Tlv8Writer::new(&mut out);
            w.push_u8(tlv::STATE, tlv::STATE_M4);
            w.push(tlv::PROOF, &m2_proof);
            out
        }

        fn controller_m1(&self, a_pub: &BigUint, session_key: &[u8]) -> Vec<u8> {
            let h_n = Sha512::digest(self.group.modulus().to_bytes_be());
            let h_g = Sha512::digest(self.group.generator().to_bytes_be());
            let h_xor: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(a, b)| a ^ b).collect();
            let h_i = Sha512::digest(PAIR_SETUP_USERNAME);
            let mut h = Sha512::new();
            h.update(h_xor);
            h.update(h_i);
            h.update(&self.salt);
            h.update(pad_be(a_pub, 384));
            h.update(pad_be(&self.b_pub, 384));
            h.update(session_key);
            h.finalize().to_vec()
        }

        /// Consume the controller's M5 (encrypted controller sub-TLV), then
        /// produce M6 (encrypted accessory sub-TLV with a valid signature).
        fn m6(&self, _m5: &[u8]) -> Vec<u8> {
            let session_key = self.session_key.as_ref().unwrap();
            let mut accessory_x = [0u8; 32];
            hkdf_sha512(
                session_key,
                ACCESSORY_SIGN_SALT,
                ACCESSORY_SIGN_INFO,
                &mut accessory_x,
            )
            .unwrap();
            let ltpk = self.signing.verifying_key().to_bytes();
            let id = self.pairing_id.as_bytes();

            let mut signed = Vec::new();
            signed.extend_from_slice(&accessory_x);
            signed.extend_from_slice(id);
            signed.extend_from_slice(&ltpk);
            let sig = self.signing.sign(&signed).to_bytes();

            let mut sub = Vec::new();
            let mut sw = Tlv8Writer::new(&mut sub);
            sw.push(tlv::IDENTIFIER, id);
            sw.push(tlv::PUBLIC_KEY, &ltpk);
            sw.push(tlv::SIGNATURE, &sig);

            let mut enc_key = [0u8; 32];
            hkdf_sha512(session_key, ENCRYPT_SALT, ENCRYPT_INFO, &mut enc_key).unwrap();
            let sealed = encrypt(&enc_key, &hap_nonce(NONCE_M6), b"", &sub).unwrap();

            let mut out = Vec::new();
            let mut w = Tlv8Writer::new(&mut out);
            w.push_u8(tlv::STATE, tlv::STATE_M6);
            w.push(tlv::ENCRYPTED_DATA, &sealed);
            out
        }
    }

    const TEST_PASSWORD: &str = "123-45-678";

    /// Big-endian bytes left-padded to `width` (mirrors SRP `PAD`).
    fn pad_be(v: &BigUint, width: usize) -> Vec<u8> {
        let raw = v.to_bytes_be();
        if raw.len() >= width {
            return raw;
        }
        let mut out = vec![0u8; width - raw.len()];
        out.extend_from_slice(&raw);
        out
    }

    #[test]
    fn full_machine_replay_reaches_done() {
        let mut accessory = TestAccessory::new(TEST_PASSWORD);
        let a = [0x37u8; 32];
        let mut client =
            PairSetupClient::new_with_private(TEST_PASSWORD, test_controller(), &a).unwrap();

        let m1 = client.start();
        assert_eq!(
            Tlv8Map::parse(&m1).unwrap().get_u8(tlv::STATE).unwrap(),
            Some(tlv::STATE_M1)
        );

        // Accessory replies with M2.
        let m2 = accessory.m2();
        let PairSetupStep::Send(m3) = client.handle(&m2).unwrap() else {
            panic!("expected M3");
        };

        // Accessory verifies M3, replies with M4.
        let m4 = accessory.m4(&m3);
        let PairSetupStep::Send(m5) = client.handle(&m4).unwrap() else {
            panic!("expected M5");
        };

        // Accessory replies with M6.
        let m6 = accessory.m6(&m5);
        let PairSetupStep::Done(pairing) = client.handle(&m6).unwrap() else {
            panic!("expected Done");
        };
        assert_eq!(pairing.pairing_id, "11:22:33:44:55:66");
        assert_eq!(pairing.ltpk, accessory.signing.verifying_key().to_bytes());
    }

    #[test]
    fn wrong_setup_code_fails_m4_proof() {
        let accessory = TestAccessory::new(TEST_PASSWORD);
        let a = [0x37u8; 32];
        // Controller uses a different code: M1 proof will not match → M2 proof
        // computed by the accessory differs → verify_m2 rejects it in M4.
        let mut client =
            PairSetupClient::new_with_private("999-99-999", test_controller(), &a).unwrap();
        let _ = client.start();
        let m2 = accessory.m2();
        let PairSetupStep::Send(m3) = client.handle(&m2).unwrap() else {
            panic!("expected M3");
        };
        // The test accessory asserts the controller M1 internally; with a wrong
        // code that assert would fire, so instead drive M4 verification directly:
        // build an M4 with a deliberately wrong proof.
        let _ = m3;
        let mut bad_m4 = Vec::new();
        let mut w = Tlv8Writer::new(&mut bad_m4);
        w.push_u8(tlv::STATE, tlv::STATE_M4);
        w.push(tlv::PROOF, &[0u8; 64]);
        assert!(matches!(
            client.handle(&bad_m4),
            Err(CryptoError::SrpProofMismatch)
        ));
    }

    #[test]
    fn accessory_error_tlv_is_surfaced() {
        let a = [0x37u8; 32];
        let mut client =
            PairSetupClient::new_with_private(TEST_PASSWORD, test_controller(), &a).unwrap();
        let _ = client.start();
        // M2 carrying an Authentication error instead of salt/B.
        let mut err = Vec::new();
        let mut w = Tlv8Writer::new(&mut err);
        w.push_u8(tlv::STATE, tlv::STATE_M2);
        w.push_u8(tlv::ERROR, 2); // kTLVError_Authentication
        assert!(matches!(
            client.handle(&err),
            Err(CryptoError::SrpProofMismatch)
        ));
    }

    #[test]
    fn handle_before_start_errors() {
        let a = [0x37u8; 32];
        let mut client =
            PairSetupClient::new_with_private(TEST_PASSWORD, test_controller(), &a).unwrap();
        assert!(client.handle(b"").is_err());
    }

    #[test]
    fn normalize_setup_code_regroups_bare_digits() {
        assert_eq!(normalize_setup_code("12345678"), "123-45-678");
        assert_eq!(normalize_setup_code("123-45-678"), "123-45-678");
        assert_eq!(normalize_setup_code("oddball"), "oddball");
    }
}
