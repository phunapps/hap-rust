//! SRP-6a (RFC 5054) Secure Remote Password protocol, controller (client) side.
//!
//! This module implements the SRP-6a value flow *generically* over the group
//! (the safe-prime modulus `N` and generator `g`) and the hash function `H`, so
//! the exact same code is validated against RFC 5054 Appendix B (the 1024-bit
//! group with SHA-1) and instantiated for HAP Pair Setup (the RFC 5054
//! Appendix A 3072-bit group with SHA-512). Only the *protocol* lives here;
//! modular exponentiation comes from `num-bigint` and the hash from a vetted
//! [`Digest`] implementation — primitives are never reimplemented.
//!
//! Notation follows RFC 5054 / the HAP specification:
//!
//! - `N`, `g` — the group modulus and generator.
//! - `H` — the group hash (`SHA-1` for the RFC test, `SHA-512` for HAP).
//! - `PAD(x)` — `x`'s big-endian bytes left-padded with zeros to `len(N)`.
//! - `k = H(N | PAD(g))`
//! - `x = H(s | H(I | ":" | P))` (`s` salt, `I` username, `P` password)
//! - `v = g^x mod N` (the verifier the accessory stores)
//! - `A = g^a mod N` (client ephemeral public, `a` private)
//! - `B = (k*v + g^b) mod N` (server ephemeral public, `b` private)
//! - `u = H(PAD(A) | PAD(B))`
//! - client `S = (B - k * g^x) ^ (a + u*x) mod N`
//! - `K = H(S)` (the session key)
//! - `M1 = H( H(N) XOR H(g) | H(I) | s | PAD(A) | PAD(B) | K )`
//! - `M2 = H( PAD(A) | M1 | K )`

// This module is the SRP-6a surface the Pair Setup client state machine (a
// later implementation chunk) drives; until that wiring lands, the only
// in-crate consumer is the test module, so the items read as dead code in a
// plain build. The functions are exercised by the RFC 5054 / HAP test suite.
#![allow(dead_code)]

use num_bigint::BigUint;
use num_traits::Zero;
use sha2::Digest;

use crate::error::{CryptoError, Result};

/// An SRP-6a group: the safe-prime modulus `N` and the generator `g`.
///
/// Both the RFC 5054 1024-bit group (`g = 2`) used by the known-answer test and
/// the RFC 5054 Appendix A 3072-bit group (`g = 5`) used by HAP are expressed
/// as values of this type. Construct one from the published big-endian bytes
/// with [`SrpGroup::new`].
#[derive(Clone)]
pub(crate) struct SrpGroup {
    /// The safe-prime modulus `N`.
    n: BigUint,
    /// The generator `g`.
    g: BigUint,
    /// `len(N)` in bytes; the target width for every `PAD()`.
    n_len: usize,
}

impl SrpGroup {
    /// Build a group from the modulus `N` and generator `g` as big-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SrpBadParameters`] if `N` is zero.
    pub(crate) fn new(n_be: &[u8], g_be: &[u8]) -> Result<Self> {
        let n = BigUint::from_bytes_be(n_be);
        if n.is_zero() {
            return Err(CryptoError::SrpBadParameters("group modulus N is zero"));
        }
        let n_len = usize::try_from(n.bits().div_ceil(8))
            .map_err(|_| CryptoError::Encoding("group modulus N too large for this platform"))?;
        Ok(Self {
            n,
            g: BigUint::from_bytes_be(g_be),
            n_len,
        })
    }

    /// The modulus `N`.
    pub(crate) fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// The generator `g`.
    pub(crate) fn generator(&self) -> &BigUint {
        &self.g
    }

    /// `len(N)` in bytes — the width every `PAD()` targets.
    pub(crate) fn n_len(&self) -> usize {
        self.n_len
    }

    /// Left-pad `value`'s big-endian bytes to `len(N)` (RFC 5054 `PAD`).
    pub(crate) fn pad(&self, value: &BigUint) -> Vec<u8> {
        pad_be(value, self.n_len)
    }
}

/// Left-pad `value`'s big-endian bytes with leading zeros to exactly `width`.
///
/// If `value` already needs `width` bytes the bytes are returned unchanged; a
/// value wider than `width` (which the SRP flow never produces, since every
/// quantity is reduced mod `N`) is returned at its natural width.
fn pad_be(value: &BigUint, width: usize) -> Vec<u8> {
    let raw = value.to_bytes_be();
    if raw.len() >= width {
        return raw;
    }
    let mut out = vec![0u8; width - raw.len()];
    out.extend_from_slice(&raw);
    out
}

/// `k = H(N | PAD(g))`, the SRP-6a multiplier, as a `BigUint`.
pub(crate) fn compute_k<D: Digest>(group: &SrpGroup) -> BigUint {
    let mut h = D::new();
    h.update(group.modulus().to_bytes_be());
    h.update(group.pad(group.generator()));
    BigUint::from_bytes_be(&h.finalize())
}

/// `x = H(s | H(I | ":" | P))`, the private key derived from the credentials.
///
/// `salt` is `s`, `username` is `I`, `password` is `P`.
pub(crate) fn compute_x<D: Digest>(salt: &[u8], username: &[u8], password: &[u8]) -> BigUint {
    let inner = {
        let mut h = D::new();
        h.update(username);
        h.update(b":");
        h.update(password);
        h.finalize()
    };
    let mut h = D::new();
    h.update(salt);
    h.update(inner);
    BigUint::from_bytes_be(&h.finalize())
}

/// `v = g^x mod N`, the password verifier the accessory stores.
pub(crate) fn compute_v(group: &SrpGroup, x: &BigUint) -> BigUint {
    group.generator().modpow(x, group.modulus())
}

/// `u = H(PAD(A) | PAD(B))`, the random scrambling parameter.
pub(crate) fn compute_u<D: Digest>(group: &SrpGroup, a_pub: &BigUint, b_pub: &BigUint) -> BigUint {
    let mut h = D::new();
    h.update(group.pad(a_pub));
    h.update(group.pad(b_pub));
    BigUint::from_bytes_be(&h.finalize())
}

/// `B = (k*v + g^b) mod N`, the server ephemeral public key.
///
/// Lives here (rather than only on the client) so tests can act as the
/// verifier and drive the exchange end to end.
pub(crate) fn compute_b(group: &SrpGroup, k: &BigUint, v: &BigUint, b_priv: &BigUint) -> BigUint {
    let n = group.modulus();
    let gb = group.generator().modpow(b_priv, n);
    (((k * v) % n) + gb) % n
}

/// SRP-6a controller (client) state for a single exchange, generic over the
/// hash `D` and parameterised by the [`SrpGroup`].
pub(crate) struct SrpClient<D: Digest> {
    group: SrpGroup,
    username: Vec<u8>,
    /// `a` — the client private ephemeral exponent.
    a: BigUint,
    /// `A = g^a mod N` — the client public ephemeral.
    a_pub: BigUint,
    _hash: core::marker::PhantomData<D>,
}

impl<D: Digest> SrpClient<D> {
    /// Build a client with a caller-supplied private exponent `a`.
    ///
    /// This is the deterministic constructor used by the RFC 5054 known-answer
    /// test (which fixes `a`) and by replay harnesses. Production code wraps a
    /// CSPRNG-sourced `a` (a later chunk adds the randomised constructor).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SrpBadParameters`] if the resulting public
    /// ephemeral `A` is congruent to zero mod `N`, which SRP-6a forbids.
    pub(crate) fn with_private(group: SrpGroup, username: &[u8], a: BigUint) -> Result<Self> {
        let a_pub = group.generator().modpow(&a, group.modulus());
        if (&a_pub % group.modulus()).is_zero() {
            return Err(CryptoError::SrpBadParameters(
                "client public A is zero mod N",
            ));
        }
        Ok(Self {
            group,
            username: username.to_vec(),
            a,
            a_pub,
            _hash: core::marker::PhantomData,
        })
    }

    /// The client public ephemeral `A` as a `BigUint`.
    pub(crate) fn a_pub(&self) -> &BigUint {
        &self.a_pub
    }

    /// `PAD(A)` — the client public ephemeral in wire form (`len(N)` bytes).
    pub(crate) fn a_pub_bytes(&self) -> Vec<u8> {
        self.group.pad(&self.a_pub)
    }

    /// The group this client is operating in.
    pub(crate) fn group(&self) -> &SrpGroup {
        &self.group
    }

    /// Compute the client premaster secret `S = (B - k*g^x)^(a + u*x) mod N`.
    ///
    /// `salt` is the accessory salt `s`, `b_pub` is the accessory public `B`,
    /// and `password` is the setup code `P`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SrpBadParameters`] if `B` is congruent to zero
    /// mod `N`, and [`CryptoError::SrpProofMismatch`] if the scrambling
    /// parameter `u` is zero — both are mandatory SRP-6a abort conditions.
    pub(crate) fn premaster(
        &self,
        salt: &[u8],
        password: &[u8],
        b_pub: &BigUint,
    ) -> Result<BigUint> {
        let n = self.group.modulus();
        if (b_pub % n).is_zero() {
            return Err(CryptoError::SrpBadParameters(
                "server public B is zero mod N",
            ));
        }
        let k = compute_k::<D>(&self.group);
        let x = compute_x::<D>(salt, &self.username, password);
        let u = compute_u::<D>(&self.group, &self.a_pub, b_pub);
        if u.is_zero() {
            return Err(CryptoError::SrpProofMismatch);
        }

        // base = (B - k * g^x) mod N, computed in the additive group of Z_N to
        // stay non-negative even when k*g^x exceeds B.
        let gx = self.group.generator().modpow(&x, n);
        let kgx = (&k * &gx) % n;
        let base = (b_pub + n - kgx) % n;
        let exp = &self.a + (&u * &x);
        Ok(base.modpow(&exp, n))
    }

    /// `K = H(S)`, the SRP session key, from a premaster secret `S`.
    pub(crate) fn session_key(&self, premaster: &BigUint) -> Vec<u8> {
        let mut h = D::new();
        h.update(self.group.pad(premaster));
        h.finalize().to_vec()
    }

    /// The controller proof `M1 = H( H(N) XOR H(g) | H(I) | s | PAD(A) | PAD(B) | K )`.
    pub(crate) fn proof_m1(&self, salt: &[u8], b_pub: &BigUint, session_key: &[u8]) -> Vec<u8> {
        let h_n = {
            let mut h = D::new();
            h.update(self.group.modulus().to_bytes_be());
            h.finalize()
        };
        let h_g = {
            let mut h = D::new();
            h.update(self.group.generator().to_bytes_be());
            h.finalize()
        };
        let h_xor: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(a, b)| a ^ b).collect();
        let h_i = {
            let mut h = D::new();
            h.update(&self.username);
            h.finalize()
        };

        let mut h = D::new();
        h.update(h_xor);
        h.update(h_i);
        h.update(salt);
        h.update(self.group.pad(&self.a_pub));
        h.update(self.group.pad(b_pub));
        h.update(session_key);
        h.finalize().to_vec()
    }

    /// The expected accessory proof `M2 = H( PAD(A) | M1 | K )`.
    pub(crate) fn expected_m2(&self, m1: &[u8], session_key: &[u8]) -> Vec<u8> {
        let mut h = D::new();
        h.update(self.group.pad(&self.a_pub));
        h.update(m1);
        h.update(session_key);
        h.finalize().to_vec()
    }

    /// Verify the accessory proof `M2` in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SrpProofMismatch`] if `received` does not equal
    /// the locally computed `M2`.
    pub(crate) fn verify_m2(&self, m1: &[u8], session_key: &[u8], received: &[u8]) -> Result<()> {
        let expected = self.expected_m2(m1, session_key);
        if ct_eq(&expected, received) {
            Ok(())
        } else {
            Err(CryptoError::SrpProofMismatch)
        }
    }
}

/// Constant-time byte-slice equality, used for SRP proof comparison.
///
/// Returns `true` only if both slices have the same length and the same
/// contents. The length check short-circuits (lengths are not secret); the
/// content comparison is constant time via [`subtle`].
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
// Test code only: CLAUDE.md carves out `unwrap`/`expect` for tests with a
// documented justification. The values come from fixed published vectors, so a
// failed `unwrap` here is itself a test failure, which is the desired behaviour.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sha1::Sha1;
    use sha2::Sha512;

    /// Decode a hex string that may contain whitespace/newlines.
    fn h(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(char::is_ascii_hexdigit).collect();
        hex::decode(cleaned).unwrap()
    }

    fn big(s: &str) -> BigUint {
        BigUint::from_bytes_be(&h(s))
    }

    // ---- RFC 5054 Appendix B known-answer test (1024-bit group, SHA-1) ----
    //
    // All literals below are the published values from RFC 5054 Appendix B:
    //   I = "alice", P = "password123", H = SHA-1, g = 2, the 1024-bit N, and
    //   the fixed salt s, private exponents a and b, and resulting intermediate
    //   values x, v, A, B, u, and the premaster secret. These are real, public
    //   known-answer values; we assert our generic SRP-6a reproduces them.

    const RFC5054_N_1024: &str = "\
        EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C \
        9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4 \
        8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29 \
        7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A \
        FD5138FE 8376435B 9FC61D2F C0EB06E3";

    const RFC5054_SALT: &str = "BEB25379 D1A8581E B5A72767 3A2441EE";
    const RFC5054_X: &str = "94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124";
    const RFC5054_V: &str = "\
        7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812 \
        9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5 \
        C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5 \
        EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78 \
        E955A5E2 9E7AB245 DB2BE315 E2099AFB";

    const RFC5054_A_PRIV: &str = "\
        60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD \
        DA2D4393";
    const RFC5054_B_PRIV: &str = "\
        E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 \
        05284D20";
    const RFC5054_A_PUB: &str = "\
        61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4 \
        4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC \
        8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44 \
        BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA \
        B349EF5D 76988A36 72FAC47B 0769447B";
    const RFC5054_B_PUB: &str = "\
        BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011 \
        BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99 \
        6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA \
        37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE \
        EB4012B7 D7665238 A8E3FB00 4B117B58";
    const RFC5054_U: &str = "CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019";
    const RFC5054_PREMASTER: &str = "\
        B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D \
        233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C \
        41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F \
        3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D \
        C346D7E4 74B29EDE 8A469FFE CA686E5A";

    fn rfc5054_group() -> SrpGroup {
        SrpGroup::new(&h(RFC5054_N_1024), &[2]).unwrap()
    }

    #[test]
    fn rfc5054_x_matches() {
        let x = compute_x::<Sha1>(&h(RFC5054_SALT), b"alice", b"password123");
        assert_eq!(x, big(RFC5054_X));
    }

    #[test]
    fn rfc5054_v_matches() {
        let group = rfc5054_group();
        let x = compute_x::<Sha1>(&h(RFC5054_SALT), b"alice", b"password123");
        let v = compute_v(&group, &x);
        assert_eq!(v, big(RFC5054_V));
    }

    #[test]
    fn rfc5054_a_pub_matches() {
        let group = rfc5054_group();
        let client = SrpClient::<Sha1>::with_private(group, b"alice", big(RFC5054_A_PRIV)).unwrap();
        assert_eq!(client.a_pub(), &big(RFC5054_A_PUB));
    }

    #[test]
    fn rfc5054_b_pub_matches() {
        let group = rfc5054_group();
        let x = compute_x::<Sha1>(&h(RFC5054_SALT), b"alice", b"password123");
        let v = compute_v(&group, &x);
        let k = compute_k::<Sha1>(&group);
        let b = compute_b(&group, &k, &v, &big(RFC5054_B_PRIV));
        assert_eq!(b, big(RFC5054_B_PUB));
    }

    #[test]
    fn rfc5054_u_matches() {
        let group = rfc5054_group();
        let u = compute_u::<Sha1>(&group, &big(RFC5054_A_PUB), &big(RFC5054_B_PUB));
        assert_eq!(u, big(RFC5054_U));
    }

    #[test]
    fn rfc5054_premaster_matches() {
        let group = rfc5054_group();
        let client = SrpClient::<Sha1>::with_private(group, b"alice", big(RFC5054_A_PRIV)).unwrap();
        let premaster = client
            .premaster(&h(RFC5054_SALT), b"password123", &big(RFC5054_B_PUB))
            .unwrap();
        assert_eq!(premaster, big(RFC5054_PREMASTER));
    }

    // ---- HAP parameter set: RFC 5054 Appendix A 3072-bit group, SHA-512 ----
    //
    // Self-consistency end-to-end: a test-only verifier and the client agree on
    // the session key K and both proofs verify. This proves the generic core is
    // internally consistent under the HAP parameters. It deliberately asserts
    // NO captured/spec HAP-parameter hex — the real cross-check against a
    // captured trace is the ignored placeholder below.

    /// RFC 5054 Appendix A 3072-bit group prime `N` (g = 5).
    const RFC5054_N_3072: &str = "\
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 \
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD \
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 \
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED \
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D \
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F \
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D \
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B \
        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 \
        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 \
        15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64 \
        ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7 \
        ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B \
        F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C \
        BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 \
        43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF";

    fn hap_group() -> SrpGroup {
        SrpGroup::new(&h(RFC5054_N_3072), &[5]).unwrap()
    }

    #[test]
    fn hap_params_self_consistent_end_to_end() {
        let group = hap_group();
        let username = b"Pair-Setup";
        let salt = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
        let setup_code = b"123-45-678";

        // Accessory (verifier) side: compute the verifier from the credentials,
        // pick a fixed private b, derive B.
        let x_priv = compute_x::<Sha512>(salt, username, setup_code);
        let verifier = compute_v(&group, &x_priv);
        let multiplier = compute_k::<Sha512>(&group);
        let b_priv = BigUint::from_bytes_be(&[0x42u8; 32]);
        let b_pub = compute_b(&group, &multiplier, &verifier, &b_priv);

        // Controller (client) side: fixed private a, derive A, premaster, K.
        let a_priv = BigUint::from_bytes_be(&[0x37u8; 32]);
        let client = SrpClient::<Sha512>::with_private(group.clone(), username, a_priv).unwrap();
        let client_pm = client.premaster(salt, setup_code, &b_pub).unwrap();
        let client_key = client.session_key(&client_pm);

        // The wire-form public ephemeral is PAD(A): exactly len(N) bytes.
        assert_eq!(client.a_pub_bytes().len(), client.group().n_len());
        assert_eq!(client.group().n_len(), 384); // 3072-bit group => 384 bytes

        // Server premaster S = (A * v^u) ^ b mod N; both sides must match.
        let modulus = group.modulus();
        let scrambler = compute_u::<Sha512>(&group, client.a_pub(), &b_pub);
        let server_pm = {
            let vu = verifier.modpow(&scrambler, modulus);
            let base = (client.a_pub() * &vu) % modulus;
            base.modpow(&b_priv, modulus)
        };
        assert_eq!(client_pm, server_pm, "premaster secrets must agree");

        // Proofs round-trip: M1 verifies, M2 verifies, both in constant time.
        let m1 = client.proof_m1(salt, &b_pub, &client_key);
        let m2 = client.expected_m2(&m1, &client_key);
        client.verify_m2(&m1, &client_key, &m2).unwrap();

        // A tampered M2 must be rejected.
        let mut bad = m2.clone();
        bad[0] ^= 0x01;
        assert!(client.verify_m2(&m1, &client_key, &bad).is_err());
    }

    #[test]
    fn ct_eq_behaviour() {
        assert!(ct_eq(b"abcdef", b"abcdef"));
        assert!(!ct_eq(b"abcdef", b"abcdeg"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    /// Cross-verification of the HAP parameter set (3072-bit / SHA-512) against
    /// a captured aiohomekit Pair Setup trace is DEFERRED until real hardware
    /// is available (see the M2 plan, Task 1). When the capture lands under
    /// `test-vectors/srp/`, this test should load those fixtures and assert the
    /// HAP-parameter `k`, `x`, `A`, `B`, `u`, `S`, `M1`, `M2` byte-for-byte.
    #[test]
    #[ignore = "pending captured aiohomekit SRP trace under test-vectors/srp/"]
    fn hap_params_match_captured_trace() {
        unimplemented!("load test-vectors/srp/ fixtures once captured");
    }
}
