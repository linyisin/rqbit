// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-18: Message Stream Encryption /
// Protocol Encryption (MSE/PE), the obfuscated BitTorrent handshake implemented by Vuze, libtorrent
// and qBittorrent. Licensed under Apache-2.0 like the rest of rqbit.
//
// Spec: https://wiki.vuze.com/w/Message_Stream_Encryption
//
//   1 A->B: Diffie-Hellman Ya, PadA
//   2 B->A: Diffie-Hellman Yb, PadB
//   3 A->B: HASH('req1', S), HASH('req2', SKEY) xor HASH('req3', S),
//           ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA)), ENCRYPT(IA)
//   4 B->A: ENCRYPT(VC, crypto_select, len(padD), padD), ENCRYPT2(Payload Stream)
//   5 A->B: ENCRYPT2(Payload Stream)
//
// P is the 768-bit prime below, G = 2, private keys are 160 random bits, HASH is SHA-1, VC is
// 8 zero bytes, SKEY is the info hash. A encrypts with RC4(HASH('keyA', S, SKEY)) and B with
// RC4(HASH('keyB', S, SKEY)), both discarding the first 1024 bytes of keystream. Pads are 0-512
// random bytes, which is why the receiver has to search for a synchronisation point.
//
// `crypto_select` picks how the payload stream after the handshake is sent: RC4 (everything
// encrypted) or plaintext (only the handshake is obfuscated).

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{Context as _, bail};
use librqbit_core::hash_id::Id20;
use num_bigint::BigUint;
use sha1w::{ISha1, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// What we do about encryption, like qBittorrent's "Encryption mode".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EncryptionPolicy {
    /// Plaintext only: never start an encrypted handshake, refuse incoming encrypted ones.
    /// This is librqbit's historical behaviour and the default.
    #[default]
    Disabled,
    /// Try an encrypted handshake on outgoing connections and fall back to plaintext if the peer
    /// doesn't speak it; accept both on incoming connections. RC4 is chosen when both are offered.
    Enabled,
    /// Encrypted connections with RC4 only.
    Required,
}

/// The first 20 bytes of a plaintext BitTorrent handshake.
pub const BT_HANDSHAKE_PREFIX: &[u8; 20] = b"\x13BitTorrent protocol";

const P_HEX: &[u8] = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563";
const KEY_LEN: usize = 96;
const VC: [u8; 8] = [0; 8];
const MAX_PAD: usize = 512;
pub const CRYPTO_PLAINTEXT: u32 = 0x01;
pub const CRYPTO_RC4: u32 = 0x02;

// ───────────────────────────── RC4 ─────────────────────────────

#[derive(Clone)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Rc4 {
        let mut s = [0u8; 256];
        for (v, i) in s.iter_mut().zip(0..=u8::MAX) {
            *v = i;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Rc4 { s, i: 0, j: 0 }
    }

    /// RC4 as used by MSE: the first 1024 bytes of keystream are thrown away.
    fn for_mse(key: &[u8]) -> Rc4 {
        let mut rc4 = Rc4::new(key);
        rc4.apply(&mut [0u8; 1024]);
        rc4
    }

    /// Encrypts or decrypts in place (RC4 is symmetric).
    pub fn apply(&mut self, data: &mut [u8]) {
        for b in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *b ^= k;
        }
    }
}

// ───────────────────────────── Diffie-Hellman ─────────────────────────────

struct KeyPair {
    private: BigUint,
    public: [u8; KEY_LEN],
}

fn prime() -> BigUint {
    BigUint::parse_bytes(P_HEX, 16).expect("valid prime")
}

fn to_key_bytes(n: &BigUint) -> [u8; KEY_LEN] {
    let bytes = n.to_bytes_be();
    let mut out = [0u8; KEY_LEN];
    out[KEY_LEN - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn generate_keypair() -> KeyPair {
    let private = BigUint::from_bytes_be(&rand::random::<[u8; 20]>());
    let public = BigUint::from(2u32).modpow(&private, &prime());
    KeyPair { private, public: to_key_bytes(&public) }
}

fn shared_secret(keys: &KeyPair, other_public: &[u8]) -> anyhow::Result<[u8; KEY_LEN]> {
    let p = prime();
    let y = BigUint::from_bytes_be(other_public);
    // Reject degenerate keys (0, 1, p-1, >= p).
    if y <= BigUint::from(1u32) || y >= &p - 1u32 {
        bail!("invalid Diffie-Hellman public key");
    }
    Ok(to_key_bytes(&y.modpow(&keys.private, &p)))
}

fn hash(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finish()
}

fn xor20(a: &[u8; 20], b: &[u8; 20]) -> [u8; 20] {
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn random_pad() -> Vec<u8> {
    let len = rand::random::<u16>() as usize % (MAX_PAD + 1);
    (0..len).map(|_| rand::random::<u8>()).collect()
}

// ───────────────────────────── handshake ─────────────────────────────

/// Result of a successful MSE handshake.
pub struct Established {
    /// Decrypts the payload stream (None = plaintext was selected).
    pub read_cipher: Option<Rc4>,
    /// Encrypts the payload stream (None = plaintext was selected).
    pub write_cipher: Option<Rc4>,
    /// Payload bytes already received and decrypted: on the receiving side this starts with the
    /// initial payload (IA), followed by whatever came after the handshake.
    pub prefix: Vec<u8>,
    /// The torrent the connection is for (the SKEY).
    pub info_hash: Id20,
    pub selected: u32,
}

/// Reads from the stream into a buffer as needed.
struct Incoming<'a, R> {
    reader: &'a mut R,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> Incoming<'_, R> {
    async fn ensure(&mut self, n: usize) -> anyhow::Result<()> {
        let mut tmp = [0u8; 2048];
        while self.buf.len() < n {
            let read = self.reader.read(&mut tmp).await?;
            if read == 0 {
                bail!("connection closed during the encrypted handshake");
            }
            self.buf.extend_from_slice(&tmp[..read]);
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        self.buf.drain(..n).collect()
    }

    /// Finds `pattern`, which must start within the first `window` bytes, and consumes everything
    /// up to and including it.
    async fn sync(&mut self, pattern: &[u8], window: usize) -> anyhow::Result<()> {
        loop {
            if let Some(pos) = self.buf.windows(pattern.len()).position(|w| w == pattern) {
                if pos > window {
                    bail!("encrypted handshake: synchronisation point not found");
                }
                self.buf.drain(..pos + pattern.len());
                return Ok(());
            }
            if self.buf.len() >= window + pattern.len() {
                bail!("encrypted handshake: synchronisation point not found");
            }
            let have = self.buf.len();
            self.ensure(have + 1).await?;
        }
    }
}

fn select(provided: u32, policy: EncryptionPolicy) -> anyhow::Result<u32> {
    let rc4_ok = provided & CRYPTO_RC4 != 0;
    let plain_ok = provided & CRYPTO_PLAINTEXT != 0 && policy != EncryptionPolicy::Required;
    match (rc4_ok, plain_ok) {
        (true, _) => Ok(CRYPTO_RC4),
        (false, true) => Ok(CRYPTO_PLAINTEXT),
        _ => bail!("encrypted handshake: no acceptable crypto method offered ({provided:#x})"),
    }
}

/// Outgoing side (A). `policy` must not be `Disabled`.
pub async fn initiate<R, W>(
    reader: &mut R,
    writer: &mut W,
    info_hash: Id20,
    policy: EncryptionPolicy,
) -> anyhow::Result<Established>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let keys = generate_keypair();
    let mut msg1 = keys.public.to_vec();
    msg1.extend_from_slice(&random_pad());
    writer.write_all(&msg1).await?;

    let mut incoming = Incoming { reader, buf: Vec::new() };
    incoming.ensure(KEY_LEN).await?;
    let yb = incoming.take(KEY_LEN);
    let s = shared_secret(&keys, &yb)?;
    let skey = info_hash.0;

    let mut enc = Rc4::for_mse(&hash(&[b"keyA", &s, &skey]));
    let mut dec = Rc4::for_mse(&hash(&[b"keyB", &s, &skey]));

    let provide = match policy {
        EncryptionPolicy::Required => CRYPTO_RC4,
        _ => CRYPTO_RC4 | CRYPTO_PLAINTEXT,
    };
    let mut msg3 = Vec::with_capacity(40 + 16);
    msg3.extend_from_slice(&hash(&[b"req1", &s]));
    msg3.extend_from_slice(&xor20(&hash(&[b"req2", &skey]), &hash(&[b"req3", &s])));
    let mut encrypted = Vec::with_capacity(16);
    encrypted.extend_from_slice(&VC);
    encrypted.extend_from_slice(&provide.to_be_bytes());
    encrypted.extend_from_slice(&0u16.to_be_bytes()); // len(PadC)
    encrypted.extend_from_slice(&0u16.to_be_bytes()); // len(IA): the BT handshake follows normally
    enc.apply(&mut encrypted);
    msg3.extend_from_slice(&encrypted);
    writer.write_all(&msg3).await?;

    // B's ENCRYPT(VC) comes after PadB: look for VC encrypted with B's keystream.
    let mut vc = VC;
    dec.apply(&mut vc);
    incoming.sync(&vc, MAX_PAD).await?;

    incoming.ensure(6).await?;
    let mut head = incoming.take(6);
    dec.apply(&mut head);
    let selected = u32::from_be_bytes(head[0..4].try_into().unwrap());
    let pad_d = u16::from_be_bytes(head[4..6].try_into().unwrap()) as usize;
    if pad_d > MAX_PAD {
        bail!("encrypted handshake: padD too long");
    }
    incoming.ensure(pad_d).await?;
    let mut pad = incoming.take(pad_d);
    dec.apply(&mut pad);
    if selected != CRYPTO_RC4 && selected != CRYPTO_PLAINTEXT || selected & provide == 0 {
        bail!("encrypted handshake: peer selected an unsupported method ({selected:#x})");
    }

    let rc4 = selected == CRYPTO_RC4;
    let mut prefix = std::mem::take(&mut incoming.buf);
    if rc4 {
        dec.apply(&mut prefix);
    }
    Ok(Established {
        read_cipher: rc4.then_some(dec),
        write_cipher: rc4.then_some(enc),
        prefix,
        info_hash,
        selected,
    })
}

/// Incoming side (B). `already_read` are bytes consumed while detecting the protocol (the start
/// of Ya). `find_torrent` maps HASH('req2', SKEY) to the info hash of one of our torrents.
pub async fn respond<R, W>(
    reader: &mut R,
    writer: &mut W,
    already_read: &[u8],
    policy: EncryptionPolicy,
    find_torrent: impl Fn(&[u8; 20]) -> Option<Id20>,
) -> anyhow::Result<Established>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut incoming = Incoming { reader, buf: already_read.to_vec() };
    incoming.ensure(KEY_LEN).await?;
    let ya = incoming.take(KEY_LEN);

    let keys = generate_keypair();
    let mut msg2 = keys.public.to_vec();
    msg2.extend_from_slice(&random_pad());
    writer.write_all(&msg2).await?;

    let s = shared_secret(&keys, &ya)?;
    incoming.sync(&hash(&[b"req1", &s]), MAX_PAD).await?;
    incoming.ensure(20).await?;
    let obfuscated: [u8; 20] = incoming.take(20).try_into().unwrap();
    let req2 = xor20(&obfuscated, &hash(&[b"req3", &s]));
    let info_hash = find_torrent(&req2).context("encrypted handshake for a torrent we don't have")?;
    let skey = info_hash.0;

    let mut dec = Rc4::for_mse(&hash(&[b"keyA", &s, &skey]));
    let mut enc = Rc4::for_mse(&hash(&[b"keyB", &s, &skey]));

    incoming.ensure(14).await?;
    let mut head = incoming.take(14);
    dec.apply(&mut head);
    if head[0..8] != VC {
        bail!("encrypted handshake: bad verification constant");
    }
    let provided = u32::from_be_bytes(head[8..12].try_into().unwrap());
    let pad_c = u16::from_be_bytes(head[12..14].try_into().unwrap()) as usize;
    if pad_c > MAX_PAD {
        bail!("encrypted handshake: padC too long");
    }
    incoming.ensure(pad_c + 2).await?;
    let mut pad_and_len = incoming.take(pad_c + 2);
    dec.apply(&mut pad_and_len);
    let ia_len = u16::from_be_bytes(pad_and_len[pad_c..].try_into().unwrap()) as usize;
    incoming.ensure(ia_len).await?;
    let mut ia = incoming.take(ia_len);
    dec.apply(&mut ia);

    let selected = select(provided, policy)?;
    let mut msg4 = Vec::with_capacity(14);
    msg4.extend_from_slice(&VC);
    msg4.extend_from_slice(&selected.to_be_bytes());
    msg4.extend_from_slice(&0u16.to_be_bytes()); // len(padD)
    enc.apply(&mut msg4);
    writer.write_all(&msg4).await?;

    let rc4 = selected == CRYPTO_RC4;
    let mut rest = std::mem::take(&mut incoming.buf);
    if rc4 {
        dec.apply(&mut rest);
    }
    ia.extend_from_slice(&rest);
    Ok(Established {
        read_cipher: rc4.then_some(dec),
        write_cipher: rc4.then_some(enc),
        prefix: ia,
        info_hash,
        selected,
    })
}

/// HASH('req2', info_hash), what `respond`'s `find_torrent` receives.
pub fn req2_hash(info_hash: &Id20) -> [u8; 20] {
    hash(&[b"req2", &info_hash.0])
}

// ───────────────────────────── stream wrappers ─────────────────────────────

/// Serves `prefix` first, then reads from `inner`, decrypting if a cipher is set.
/// With no cipher it is just a "put these bytes back" reader.
pub struct MseReader<R> {
    inner: R,
    prefix: Vec<u8>,
    pos: usize,
    cipher: Option<Rc4>,
}

impl<R> MseReader<R> {
    pub fn new(inner: R, prefix: Vec<u8>, cipher: Option<Rc4>) -> Self {
        Self { inner, prefix, pos: 0, cipher }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for MseReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if let Some(c) = this.cipher.as_mut() {
                    c.apply(&mut buf.filled_mut()[before..]);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// Encrypts everything written (if a cipher is set). Encrypted bytes that the inner writer
/// hasn't accepted yet are kept and written before anything else.
pub struct MseWriter<W> {
    inner: W,
    cipher: Option<Rc4>,
    pending: Vec<u8>,
    pending_pos: usize,
}

impl<W> MseWriter<W> {
    pub fn new(inner: W, cipher: Option<Rc4>) -> Self {
        Self { inner, cipher, pending: Vec::new(), pending_pos: 0 }
    }
}

impl<W: AsyncWrite + Unpin> MseWriter<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")));
                }
                Poll::Ready(Ok(n)) => self.pending_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for MseWriter<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.cipher.is_none() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        // Accept the whole buffer: encrypt it into `pending` (the keystream must advance exactly
        // once per byte) and start writing it out.
        this.pending.extend_from_slice(buf);
        if let Some(c) = this.cipher.as_mut() {
            c.apply(&mut this.pending);
        }
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn rc4_known_vectors() {
        // Classic RC4 test vectors.
        for (key, plain, cipher) in [
            ("Key", "Plaintext", "BBF316E8D940AF0AD3"),
            ("Wiki", "pedia", "1021BF0420"),
            ("Secret", "Attack at dawn", "45A01F645FC35B383552544B9BF5"),
        ] {
            let mut data = plain.as_bytes().to_vec();
            Rc4::new(key.as_bytes()).apply(&mut data);
            assert_eq!(data, hex(cipher), "{key}");
        }
    }

    #[test]
    fn prime_is_768_bits_and_dh_agrees() {
        assert_eq!(prime().bits(), 768);
        let a = generate_keypair();
        let b = generate_keypair();
        assert_eq!(shared_secret(&a, &b.public).unwrap(), shared_secret(&b, &a.public).unwrap());
        assert!(shared_secret(&a, &[0u8; KEY_LEN]).is_err());
        assert!(shared_secret(&a, &[1u8]).is_err());
    }

    async fn run(
        init_policy: EncryptionPolicy,
        resp_policy: EncryptionPolicy,
        responder_has: Id20,
    ) -> (anyhow::Result<Established>, anyhow::Result<Established>) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let info_hash = Id20::new([9u8; 20]);
        let req2 = req2_hash(&responder_has);
        tokio::join!(
            initiate(&mut ar, &mut aw, info_hash, init_policy),
            respond(&mut br, &mut bw, &[], resp_policy, |h| (*h == req2).then_some(responder_has)),
        )
    }

    #[tokio::test]
    async fn handshake_picks_rc4_and_streams_roundtrip() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let info_hash = Id20::new([9u8; 20]);
        let req2 = req2_hash(&info_hash);
        let (ra, rb) = tokio::join!(
            initiate(&mut ar, &mut aw, info_hash, EncryptionPolicy::Enabled),
            respond(&mut br, &mut bw, &[], EncryptionPolicy::Enabled, |h| (*h == req2).then_some(info_hash)),
        );
        let (ea, eb) = (ra.unwrap(), rb.unwrap());
        assert_eq!((ea.selected, eb.selected), (CRYPTO_RC4, CRYPTO_RC4));
        assert_eq!(eb.info_hash, info_hash);

        let mut a_w = MseWriter::new(aw, ea.write_cipher);
        let mut a_r = MseReader::new(ar, ea.prefix, ea.read_cipher);
        let mut b_w = MseWriter::new(bw, eb.write_cipher);
        let mut b_r = MseReader::new(br, eb.prefix, eb.read_cipher);

        let big: Vec<u8> = (0..=u8::MAX).cycle().step_by(7).take(100_000).collect();
        let writer = async {
            a_w.write_all(BT_HANDSHAKE_PREFIX).await.unwrap();
            a_w.write_all(&big).await.unwrap();
            a_w.flush().await.unwrap();
        };
        let reader = async {
            let mut got = vec![0u8; 20 + big.len()];
            b_r.read_exact(&mut got).await.unwrap();
            got
        };
        let ((), got) = tokio::join!(writer, reader);
        assert_eq!(&got[..20], BT_HANDSHAKE_PREFIX);
        assert_eq!(&got[20..], &big[..]);

        b_w.write_all(b"pong").await.unwrap();
        b_w.flush().await.unwrap();
        let mut pong = [0u8; 4];
        a_r.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
    }

    #[tokio::test]
    async fn policies() {
        let ih = Id20::new([9u8; 20]);
        // Required on either side means RC4.
        for (i, r) in [
            (EncryptionPolicy::Required, EncryptionPolicy::Enabled),
            (EncryptionPolicy::Enabled, EncryptionPolicy::Required),
        ] {
            let (ra, rb) = run(i, r, ih).await;
            assert_eq!(ra.unwrap().selected, CRYPTO_RC4);
            assert_eq!(rb.unwrap().selected, CRYPTO_RC4);
        }
        // Unknown torrent: the responder gives up (the initiator then sees the connection die).
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let resp = tokio::spawn(async move {
            respond(&mut br, &mut bw, &[], EncryptionPolicy::Enabled, |_| None).await.map(|_| ())
        });
        let init = initiate(&mut ar, &mut aw, ih, EncryptionPolicy::Enabled);
        let init = tokio::time::timeout(std::time::Duration::from_secs(5), init).await;
        assert!(resp.await.unwrap().is_err());
        assert!(matches!(init, Ok(Err(_)) | Err(_)));
    }

    #[test]
    fn select_respects_policy() {
        assert_eq!(select(CRYPTO_RC4 | CRYPTO_PLAINTEXT, EncryptionPolicy::Enabled).unwrap(), CRYPTO_RC4);
        assert_eq!(select(CRYPTO_PLAINTEXT, EncryptionPolicy::Enabled).unwrap(), CRYPTO_PLAINTEXT);
        assert!(select(CRYPTO_PLAINTEXT, EncryptionPolicy::Required).is_err());
        assert!(select(0, EncryptionPolicy::Enabled).is_err());
    }

    #[tokio::test]
    async fn prefix_reader_replays_bytes() {
        let inner: &[u8] = b" world";
        let mut r = MseReader::new(inner, b"hello".to_vec(), None);
        let mut s = String::new();
        r.read_to_string(&mut s).await.unwrap();
        assert_eq!(s, "hello world");
    }
}
