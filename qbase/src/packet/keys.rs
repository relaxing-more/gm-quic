use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use futures::FutureExt;
use rustls::quic::{
    DirectionalKeys as RustlsDirectionalKeys, HeaderProtectionKey, Keys as RustlsKeys, PacketKey,
    Secrets,
};

/// Keys used to communicate in a single direction
#[derive(Clone)]
pub struct DirectionalKeys {
    /// Encrypts or decrypts a packet's headers
    pub header: Arc<dyn HeaderProtectionKey>,
    /// Encrypts or decrypts the payload of a packet
    pub packet: Arc<dyn PacketKey>,
}

impl From<RustlsDirectionalKeys> for DirectionalKeys {
    fn from(keys: RustlsDirectionalKeys) -> Self {
        Self {
            header: keys.header.into(),
            packet: keys.packet.into(),
        }
    }
}

/// Complete set of keys used to communicate with the peer
#[derive(Clone)]
pub struct Keys {
    /// Encrypts outgoing packets
    pub local: DirectionalKeys,
    /// Decrypts incoming packets
    pub remote: DirectionalKeys,
}

impl From<RustlsKeys> for Keys {
    fn from(keys: RustlsKeys) -> Self {
        Self {
            local: keys.local.into(),
            remote: keys.remote.into(),
        }
    }
}

use super::KeyPhaseBit;
use crate::{
    error::{ErrorKind, QuicError},
    role::Role,
};

#[derive(Clone)]
enum KeysState<K> {
    Pending(Option<Waker>),
    Ready(K),
    Invalid,
}

impl<K> KeysState<K> {
    fn set(&mut self, keys: K) {
        match self {
            KeysState::Pending(waker) => {
                if let Some(waker) = waker.take() {
                    waker.wake();
                }
                *self = KeysState::Ready(keys);
            }
            KeysState::Ready(_) => unreachable!("KeysState::set called twice"),
            KeysState::Invalid => unreachable!("KeysState::set called after invalidation"),
        }
    }

    fn get(&mut self) -> Option<&K> {
        match self {
            KeysState::Ready(keys) => Some(keys),
            KeysState::Pending(..) | KeysState::Invalid => None,
        }
    }

    fn invalid(&mut self) -> Option<K> {
        match std::mem::replace(self, KeysState::Invalid) {
            KeysState::Pending(waker) => {
                if let Some(waker) = waker {
                    waker.wake();
                }
                None
            }
            KeysState::Ready(keys) => Some(keys),
            KeysState::Invalid => None,
        }
    }
}

impl<K: Unpin + Clone> Future for KeysState<K> {
    type Output = Option<K>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            KeysState::Pending(waker) => {
                if waker
                    .as_ref()
                    .is_some_and(|waker| !waker.will_wake(cx.waker()))
                {
                    unreachable!(
                        "Try to get remote keys from multiple tasks! This is a bug, please report it."
                    )
                }
                *waker = Some(cx.waker().clone());
                Poll::Pending
            }
            KeysState::Ready(keys) => Poll::Ready(Some(keys.clone())),
            KeysState::Invalid => Poll::Ready(None),
        }
    }
}

/// Long packet keys, for encryption and decryption keys for those long packets,
/// as well as keys for adding and removing long packet header protection.
///
/// - When sending, obtain the local keys for packet encryption and adding header protection.
///   If the keys are not ready, skip sending the packet of this level immidiately.
/// - When receiving a packet and decrypting it, obtain the remote keys for removing header
///   protection and packet decryption.
///   If the keys are not ready, wait asynchronously until the keys to be ready to continue.
///
/// ## Note
///
/// The keys for 1-RTT packets are a separate structure, see [`ArcOneRttKeys`].
#[derive(Clone)]
pub struct ArcKeys(Arc<Mutex<KeysState<Keys>>>);

impl ArcKeys {
    fn lock_guard(&self) -> MutexGuard<'_, KeysState<Keys>> {
        self.0.lock().unwrap()
    }

    /// Create a Pending state [`ArcKeys`].
    ///
    /// For a new Quic connection, initially only the Initial key is known, and the 0-RTT
    /// and Handshake keys are unknown.
    /// Therefore, the 0-RTT and Handshake keys can be created in a Pending state, waiting
    /// for updates during the TLS handshake process.
    pub fn new_pending() -> Self {
        Self(Arc::new(KeysState::Pending(None).into()))
    }

    /// Create an [`ArcKeys`] with a specified [`rustls::quic::Keys`].
    ///
    /// The initial keys are known at first, can use this method to create the [`ArcKeys`].
    pub fn with_keys(keys: Keys) -> Self {
        Self(Arc::new(KeysState::Ready(keys).into()))
    }

    /// Asynchronously obtain the remote keys for removing header protection and packet decryption.
    ///
    /// Rreturn [`GetRemoteKeys`], which implemented Future trait.
    ///
    /// ## Example
    ///
    /// The following is only a demonstration.
    /// In fact, removing header protection and decrypting packets are far more complex!
    ///
    /// ```
    /// use qbase::packet::keys::ArcKeys;
    ///
    /// async fn decrypt_demo(keys: ArcKeys, cipher_text: &mut [u8]) {
    ///     let Some(keys) = keys.get_remote_keys().await else {
    ///         return;
    ///     };
    ///
    ///     let hpk = keys.remote.header.as_ref();
    ///     let pk = keys.remote.packet.as_ref();
    ///
    ///     // use hpk to remove header protection...
    ///     // use pk to decrypt packet body...
    /// }
    /// ```
    pub fn get_remote_keys(&self) -> GetRemoteKeys<'_, Keys> {
        GetRemoteKeys(&self.0)
    }

    /// Get the local keys for packet encryption and adding header protection.
    /// If the keys is not ready, just return None immediately.
    ///
    /// ## Example
    ///
    /// The following is only a demonstration.
    /// In fact, encrypting packets and adding header protection are far more complex!
    ///
    /// ```
    /// use qbase::packet::keys::ArcKeys;
    ///
    /// fn encrypt_demo(keys: ArcKeys, plain_text: &mut [u8]) {
    ///     let Some(keys) = keys.get_local_keys() else {
    ///         return;
    ///     };
    ///
    ///     let hpk = keys.local.header.as_ref();
    ///     let pk = keys.local.packet.as_ref();
    ///
    ///     // use pk to encrypt packet body...
    ///     // use hpk to add header protection...
    /// }
    /// ```
    pub fn get_local_keys(&self) -> Option<Keys> {
        self.lock_guard().get().cloned()
    }

    /// Set the keys to the [`ArcKeys`].
    ///
    /// As the TLS handshake progresses, higher-level keys will be obtained.
    /// These keys are set to the related [`ArcKeys`] through this method, and
    /// its internal waker will be awakened to notify the packet decryption task
    /// to continue, if the internal waker was registered.
    pub fn set_keys(&self, keys: Keys) {
        self.lock_guard().set(keys);
    }

    /// Retire the keys, which means that the keys are no longer available.
    ///
    /// This is used when the connection enters the closing state or draining state.
    /// Especially in the closing state, the return keys are used to generate the final packet
    /// containing the ConnectionClose frame, and decrypt the data packets received from the
    /// peer for a while.
    pub fn invalid(&self) -> Option<Keys> {
        self.lock_guard().invalid()
    }
}

/// To obtain the remote keys from [`ArcKeys`] or [`ArcOneRttKeys`] for removing long header protection
/// and packet decryption.
pub struct GetRemoteKeys<'k, K>(&'k Mutex<KeysState<K>>);

impl<K: Unpin + Clone> Future for GetRemoteKeys<'_, K> {
    type Output = Option<K>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(self.0.lock().unwrap()).poll_unpin(cx)
    }
}

#[derive(Clone)]
pub struct ArcZeroRttKeys {
    role: Role,
    keys: Arc<Mutex<KeysState<DirectionalKeys>>>,
}

impl ArcZeroRttKeys {
    pub fn new_pending(role: Role) -> Self {
        Self {
            role,
            keys: Arc::new(Mutex::new(KeysState::Pending(None))),
        }
    }

    fn lock_guard(&self) -> MutexGuard<'_, KeysState<DirectionalKeys>> {
        self.keys.lock().unwrap()
    }

    pub fn set_keys(&self, keys: DirectionalKeys) {
        self.lock_guard().set(keys);
    }

    pub fn get_encrypt_keys(&self) -> Option<DirectionalKeys> {
        match self.role {
            Role::Client => self.lock_guard().get().cloned(),
            Role::Server => None,
        }
    }

    pub fn get_decrypt_keys(&self) -> Option<GetRemoteKeys<'_, DirectionalKeys>> {
        match self.role {
            Role::Client => None,
            Role::Server => Some(GetRemoteKeys(&self.keys)),
        }
    }

    pub fn invalid(&self) -> Option<DirectionalKeys> {
        self.lock_guard().invalid()
    }
}

/// The packet encryption and decryption keys for 1-RTT packets,
/// which will still change after negotiation between the two endpoints.
///
/// See [key update](https://www.rfc-editor.org/rfc/rfc9001#name-key-update)
/// of [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetKeyError {
    Retired,
    Unknown,
}

/// Entry in the 1-RTT key update window.
/// Each entry represents a key generation with both send and receive keys.
#[derive(Clone)]
pub struct KeyEntry {
    /// Generation counter (0, 1, 2, ...)
    pub generation: u64,
    /// Send key for outgoing packets
    pub sk: Arc<dyn PacketKey>,
    /// Receive key for incoming packets
    pub rk: Arc<dyn PacketKey>,
    /// Record received packet number range for this key generation
    pub recv_pn_range: Option<(u64, u64)>,
}

impl KeyEntry {
    fn new(generation: u64, sk: Arc<dyn PacketKey>, rk: Arc<dyn PacketKey>) -> Self {
        Self {
            generation,
            sk,
            rk,
            recv_pn_range: None,
        }
    }

    /// Update the received packet number range when a packet is successfully decrypted.
    fn update_recv_pn(&mut self, pn: u64) {
        match &mut self.recv_pn_range {
            None => self.recv_pn_range = Some((pn, pn)),
            Some((first, last)) => {
                if pn < *first {
                    *first = pn;
                }
                if pn > *last {
                    *last = pn;
                }
            }
        }
    }
}

pub struct OneRttPacketKeys {
    /// Key update counter, incremented on each update
    counter: u64,
    /// Ordered window of key entries (max 3 generations)
    keys: VecDeque<KeyEntry>,
    /// Secrets for derive next key pair
    secrets: Option<Secrets>,
    /// Current key phase bit
    cur_phase: KeyPhaseBit,
    /// Sent packet number ranges for each generation (for ACK tracking)
    sent_pk_ranges: HashMap<u64, (u64, u64)>,
    /// Largest acknowledged packet number in 1-RTT space
    largest_acked_pn: Option<u64>,
    /// Map packet number to its generation
    sent_pk_stage: HashMap<u64, u64>,
    /// Count of unacked packets in each generation
    outstanding_pk_count: HashMap<u64, usize>,
    /// Consecutive decryption failures
    contiguous_decrypt_failures: u32,
}

impl OneRttPacketKeys {
    /// Maximum number of consecutive decryption failures before giving up
    const MAX_CONTIGUOUS_DECRYPT_FAILURES: u32 = 3;

    /// Create new [`OneRttPacketKeys`].
    ///
    /// The TLS handshake session must exchange enough information to generate the 1-RTT keys.
    fn new(remote: Box<dyn PacketKey>, local: Box<dyn PacketKey>, secrets: Secrets) -> Self {
        let sk: Arc<dyn PacketKey> = Arc::from(local);
        let rk: Arc<dyn PacketKey> = Arc::from(remote);

        let mut keys = VecDeque::new();
        let entry = KeyEntry::new(0, sk.clone(), rk);
        keys.push_back(entry);

        Self {
            counter: 0,
            keys,
            secrets: Some(secrets),
            cur_phase: KeyPhaseBit::default(),
            sent_pk_ranges: HashMap::new(),
            largest_acked_pn: None,
            sent_pk_stage: HashMap::new(),
            outstanding_pk_count: HashMap::new(),
            contiguous_decrypt_failures: 0,
        }
    }

    /// Get the local key for encrypting outgoing packets.
    ///
    /// Returns (generation, key_phase, packet_key).
    pub fn get_local_key(&self) -> (u64, KeyPhaseBit, Arc<dyn PacketKey>) {
        let entry = self.keys.back().expect("keys should not be empty");
        (entry.generation, self.cur_phase, entry.sk.clone())
    }

    /// Get the remote key for decrypting a received packet.
    ///
    /// Determines which key generation should be used based on received packet number
    /// and key phase bit. Returns (generation, key) if found.
    pub fn get_remote_key(
        &self,
        rcvd_pn: u64,
        key_phase: KeyPhaseBit,
    ) -> Result<(u64, Option<Arc<dyn PacketKey>>), &'static str> {
        // First, try to find by received pn range
        for entry in self.keys.iter() {
            if let Some((first_pn, last_pn)) = entry.recv_pn_range {
                if rcvd_pn >= first_pn && rcvd_pn <= last_pn {
                    let expected_phase = if entry.generation % 2 == 0 {
                        KeyPhaseBit::Zero
                    } else {
                        KeyPhaseBit::One
                    };
                    if key_phase == expected_phase {
                        return Ok((entry.generation, Some(entry.rk.clone())));
                    }
                }
            }
        }

        // Fallback: use candidate generations based on key_phase
        let candidates = self.candidate_generations(key_phase);
        for generation in candidates.into_iter().flatten() {
            if let Some(entry) = self.keys.iter().find(|e| e.generation == generation) {
                return Ok((entry.generation, Some(entry.rk.clone())));
            }
        }

        Err("no suitable key found")
    }

    /// Get candidate generations based on key phase bit.
    fn candidate_generations(&self, key_phase: KeyPhaseBit) -> [Option<u64>; 2] {
        if let Some(latest) = self.keys.back().map(|e| e.generation) {
            if key_phase == self.cur_phase {
                [Some(latest), latest.checked_sub(2)]
            } else {
                [latest.checked_sub(1), latest.checked_add(1)]
            }
        } else {
            [None, None]
        }
    }

    /// Called when a packet is successfully decrypted with key of generation i.
    ///
    /// This marks the generation as confirmed by received data and updates the pn range.
    fn decrypted_packet(&mut self, rcvd_pn: u64, generation: u64) -> Result<(), QuicError> {
        let max_newer_pn = self
            .keys
            .iter()
            .filter(|entry| entry.generation > generation)
            .filter_map(|entry| entry.recv_pn_range.map(|(_, last)| last))
            .max();

        if let Some(max_newer_pn) = max_newer_pn
            && rcvd_pn > max_newer_pn
        {
            return Err(QuicError::with_default_fty(
                ErrorKind::KeyUpdate,
                "key downgrade detected: higher packet number decrypted with old key",
            ));
        }

        for entry in self.keys.iter_mut() {
            if entry.generation == generation {
                entry.update_recv_pn(rcvd_pn);
                break;
            }
        }

        self.contiguous_decrypt_failures = 0;
        Ok(())
    }

    /// Called when packet decryption fails with key of generation i.
    ///
    /// Returns true if we should give up (threshold exceeded), false otherwise.
    fn decrypted_failed(&mut self, _rcvd_pn: u64, _generation: u64) -> bool {
        self.contiguous_decrypt_failures += 1;
        self.contiguous_decrypt_failures > Self::MAX_CONTIGUOUS_DECRYPT_FAILURES
    }

    /// Proactively update keys (active = true) or passively (active = false).
    ///
    /// When updating:
    /// - Derive next key pair from secrets
    /// - Add new KeyEntry to keys window
    /// - Toggle key_phase bit
    /// - Old keys may be retired if window size exceeds limit
    pub fn update(&mut self, active: bool) {
        if active {
            let latest_gen = self.keys.back().map(|e| e.generation).unwrap_or(0);
            let Some((min_sent_pn, _)) = self.sent_pk_ranges.get(&latest_gen).copied() else {
                return;
            };

            let Some(largest_acked) = self.largest_acked_pn else {
                return;
            };

            if largest_acked < min_sent_pn {
                return;
            }
        }

        let key_set = self
            .secrets
            .as_mut()
            .expect("1-RTT secrets must exist when updating keys")
            .next_packet_keys();
        self.counter += 1;

        let entry = KeyEntry::new(
            self.counter,
            Arc::from(key_set.local),
            Arc::from(key_set.remote),
        );

        self.keys.push_back(entry);
        while self.keys.len() > 3 {
            self.keys.pop_front();
        }

        self.cur_phase.toggle();
    }

    /// Validate ACK: mark packets as acknowledged and confirm key acks.
    ///
    /// When a packet in generation i is acked, we know the peer has received
    /// a packet encrypted with key i, confirming the key update.
    pub fn validate_ack(
        &mut self,
        pn: u64,
        largest_ack: u64,
        rcvd_generation: Option<u64>,
    ) -> Result<(), QuicError> {
        self.largest_acked_pn = Some(
            self.largest_acked_pn
                .map_or(largest_ack, |cur| cur.max(largest_ack)),
        );

        let Some(stage) = self.sent_pk_stage.remove(&pn) else {
            return Ok(());
        };

        if let Some(rcvd_generation) = rcvd_generation
            && stage > rcvd_generation
        {
            return Err(QuicError::with_default_fty(
                ErrorKind::KeyUpdate,
                "peer acknowledged new-key packet with older key phase",
            ));
        }

        let Some(count) = self.outstanding_pk_count.get_mut(&stage) else {
            return Ok(());
        };

        *count = count.saturating_sub(1);
        if *count == 0 {
            self.outstanding_pk_count.remove(&stage);
        }
        Ok(())
    }

    /// Record sent packet number for key update tracking
    pub fn record_sent_pk(&mut self, generation: u64, pn: u64) {
        let entry = self.sent_pk_ranges.entry(generation).or_insert((pn, pn));
        entry.0 = entry.0.min(pn);
        entry.1 = entry.1.max(pn);

        if let Some(old_stage) = self.sent_pk_stage.insert(pn, generation)
            && let Some(count) = self.outstanding_pk_count.get_mut(&old_stage)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.outstanding_pk_count.remove(&old_stage);
            }
        }

        *self.outstanding_pk_count.entry(generation).or_default() += 1;
    }

    /// Iterate through available key entries
    pub fn iter(&self) -> impl Iterator<Item = &KeyEntry> {
        self.keys.iter()
    }

    /// Get remote key candidates  based on key phase
    pub fn remote_key_candidates(&self, key_phase: KeyPhaseBit) -> [Option<u64>; 2] {
        self.candidate_generations(key_phase)
    }

    /// Get the password key for a specific generation
    pub fn key(&self, generation: u64) -> Result<Option<Arc<dyn PacketKey>>, GetKeyError> {
        for entry in self.keys.iter() {
            if entry.generation == generation {
                return Ok(Some(entry.rk.clone()));
            }
        }

        if let Some(latest) = self.keys.back().map(|e| e.generation) {
            if generation == latest + 1 {
                return Ok(None);
            }
        }

        Err(GetKeyError::Unknown)
    }

    /// Passive update in response to peer-initiated key phase change
    pub fn update_by_peer(&mut self) -> Result<(), QuicError> {
        if let Some(latest) = self.keys.back()
            && latest.recv_pn_range.is_none()
            && latest.generation > 0
        {
            return Err(QuicError::with_default_fty(
                ErrorKind::KeyUpdate,
                "received consecutive peer key updates before confirming prior update",
            ));
        }

        self.update(false);
        Ok(())
    }

    /// Record successful decryption
    pub fn on_pk_decrypted_success(&mut self, generation: u64, pn: u64) -> Result<(), QuicError> {
        self.decrypted_packet(pn, generation)
    }

    /// Record decryption failure
    pub fn on_pk_decrypt_failed(&mut self) -> bool {
        self.decrypted_failed(0, 0)
    }
}

/// The packet encryption and decryption keys for 1-RTT packets, which will still
/// change based on the KeyPhase bit in the receiving packet, or they can be update
/// it proactively locally.
///
/// For performance reasons, the second element of the tuple is the length of the
/// tag of the local packet key's underlying AEAD algorithm redundantly.
#[derive(Clone)]
pub struct ArcOneRttPacketKeys(Arc<(Mutex<OneRttPacketKeys>, usize)>);

impl ArcOneRttPacketKeys {
    /// Obtain exclusive access to the 1-RTT packet keys.
    /// During the exclusive period of encrypting or decrypting packets,
    /// the keys must not be updated elsewhere.
    pub fn lock_guard(&self) -> MutexGuard<'_, OneRttPacketKeys> {
        self.0.0.lock().unwrap()
    }

    /// Get the length of the tag of the packet key's underlying AEAD algorithm.
    ///
    /// For example, when collecting data to send, buffer needs to reserve
    /// the tag length space to fill in the integrity checksum codes.
    /// After collecting the data, encryption will be performed, and exclusive
    /// access will be obtained during encryption.
    /// There is no need to acquire the lock at the beginning to get the tag
    /// length, because nothing might be sent later, and the task might be canceled.
    /// This would save the initial locking overhead.
    /// Keeping a redundant tag length that can be obtained without locking
    /// will improve lock performance.
    pub fn tag_len(&self) -> usize {
        self.0.1
    }
}

/// The header protection keys for 1-RTT packets.
#[derive(Clone)]
pub struct HeaderProtectionKeys {
    pub local: Arc<dyn HeaderProtectionKey>,
    pub remote: Arc<dyn HeaderProtectionKey>,
}

enum OneRttKeysState {
    Pending(Option<Waker>),
    Ready {
        hpk: HeaderProtectionKeys,
        pk: ArcOneRttPacketKeys,
    },
    Invalid,
}

/// 1-RTT packet keys, for packet encryption and decryption for 1-RTT packets,
/// as well as keys for adding and removing 1-RTT packet header protection.
///
/// and its packet key will be updated.
///
/// Unlike [`ArcKeys`], the HeaderProtectionKey for 1-RTT keys does not change,
/// but the PacketKey may still be updated with changes in the KeyPhase bit.
/// Therefore, the HeaderProtectionKey and PacketKey need to be managed separately.
#[derive(Clone)]
pub struct ArcOneRttKeys(Arc<Mutex<OneRttKeysState>>);

impl ArcOneRttKeys {
    fn lock_guard(&self) -> MutexGuard<'_, OneRttKeysState> {
        self.0.lock().unwrap()
    }

    /// Create a Pending state [`ArcOneRttKeys`], waiting for the keys being ready
    /// from TLS handshaking.
    pub fn new_pending() -> Self {
        Self(Arc::new(OneRttKeysState::Pending(None).into()))
    }

    /// Set the keys to the [`ArcOneRttKeys`].
    ///
    /// As the TLS handshake progresses, 1-RTT keys will finally be obtained.
    /// And then its internal waker will be awakened to notify the packet
    /// decryption task to continue, if the internal waker was registered.
    pub fn set_keys(&self, keys: RustlsKeys, secrets: Secrets) {
        let mut state = self.lock_guard();
        match &mut *state {
            OneRttKeysState::Pending(waker) => {
                let hpk = HeaderProtectionKeys {
                    local: Arc::from(keys.local.header),
                    remote: Arc::from(keys.remote.header),
                };
                let tag_len = keys.local.packet.tag_len();
                let pk = ArcOneRttPacketKeys(Arc::new((
                    Mutex::new(OneRttPacketKeys::new(
                        keys.remote.packet,
                        keys.local.packet,
                        secrets,
                    )),
                    tag_len,
                )));
                if let Some(w) = waker.take() {
                    w.wake();
                }
                *state = OneRttKeysState::Ready { hpk, pk };
            }
            OneRttKeysState::Ready { .. } => panic!("set_keys called twice"),
            OneRttKeysState::Invalid => panic!("set_keys called after invalidation"),
        }
    }

    pub fn invalid(&self) -> Option<(HeaderProtectionKeys, ArcOneRttPacketKeys)> {
        let mut state = self.lock_guard();
        match std::mem::replace(state.deref_mut(), OneRttKeysState::Invalid) {
            OneRttKeysState::Pending(rx_waker) => {
                if let Some(waker) = rx_waker {
                    waker.wake();
                }
                None
            }
            OneRttKeysState::Ready { hpk, pk } => Some((hpk, pk)),
            OneRttKeysState::Invalid => unreachable!(),
        }
    }

    /// Get the local keys for packet encryption and adding header protection.
    /// If the keys are not ready, just return None immediately.
    ///
    /// Return a tuple of HeaderProtectionKey and OneRttPacketKeys.  
    /// The OneRttPacketKeys need to be locked during the entire packet encryption process.
    pub fn get_local_keys(&self) -> Option<(Arc<dyn HeaderProtectionKey>, ArcOneRttPacketKeys)> {
        let mut keys = self.lock_guard();
        match &mut *keys {
            OneRttKeysState::Ready { hpk, pk, .. } => Some((hpk.local.clone(), pk.clone())),
            _ => None,
        }
    }

    pub fn remote_keys(&self) -> Option<(Arc<dyn HeaderProtectionKey>, ArcOneRttPacketKeys)> {
        match &mut *self.lock_guard() {
            OneRttKeysState::Ready { hpk, pk, .. } => Some((hpk.remote.clone(), pk.clone())),
            _ => None,
        }
    }

    /// Asynchronously obtain the remote keys for removing header protection and packet decryption.
    ///
    /// Rreturn [`GetRemoteKeys`], which implemented the Future trait.
    pub fn get_remote_keys(&self) -> GetRemoteOneRttKeys<'_> {
        GetRemoteOneRttKeys(self)
    }
}

/// To obtain the remote key from [`ArcOneRttKeys`]` for removing 1-RTT header
/// protection and packet decryption.
pub struct GetRemoteOneRttKeys<'k>(&'k ArcOneRttKeys);

impl Future for GetRemoteOneRttKeys<'_> {
    type Output = Option<(Arc<dyn HeaderProtectionKey>, ArcOneRttPacketKeys)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut keys = self.0.lock_guard();
        match &mut *keys {
            OneRttKeysState::Pending(waker) => {
                if waker
                    .as_ref()
                    .is_some_and(|waker| !waker.will_wake(cx.waker()))
                {
                    unreachable!(
                        "Try to get remote keys from multiple tasks! This is a bug, please report it."
                    )
                }
                *waker = Some(cx.waker().clone());
                Poll::Pending
            }
            OneRttKeysState::Ready { hpk, pk, .. } => {
                Poll::Ready(Some((hpk.remote.clone(), pk.clone())))
            }
            OneRttKeysState::Invalid => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use rustls::{Error as RustlsError, quic::Tag};

    use super::*;

    struct DummyPacketKey;

    impl PacketKey for DummyPacketKey {
        fn encrypt_in_place(
            &self,
            _packet_number: u64,
            _header: &[u8],
            _payload: &mut [u8],
        ) -> Result<Tag, RustlsError> {
            Err(RustlsError::General("dummy key".into()))
        }

        fn decrypt_in_place<'a>(
            &self,
            _packet_number: u64,
            _header: &[u8],
            _payload: &'a mut [u8],
        ) -> Result<&'a [u8], RustlsError> {
            Err(RustlsError::General("dummy key".into()))
        }

        fn tag_len(&self) -> usize {
            16
        }

        fn confidentiality_limit(&self) -> u64 {
            u64::MAX
        }

        fn integrity_limit(&self) -> u64 {
            u64::MAX
        }
    }

    fn dummy_pk() -> Arc<dyn PacketKey> {
        Arc::new(DummyPacketKey)
    }

    fn test_keys_with_entries(entries: VecDeque<KeyEntry>) -> OneRttPacketKeys {
        OneRttPacketKeys {
            counter: entries.back().map(|e| e.generation).unwrap_or(0),
            keys: entries,
            secrets: None,
            cur_phase: KeyPhaseBit::Zero,
            sent_pk_ranges: HashMap::new(),
            largest_acked_pn: None,
            sent_pk_stage: HashMap::new(),
            outstanding_pk_count: HashMap::new(),
            contiguous_decrypt_failures: 0,
        }
    }

    #[test]
    fn key_update_error_on_consecutive_peer_updates_before_confirming_first() {
        let mut entries = VecDeque::new();
        let mut e0 = KeyEntry::new(0, dummy_pk(), dummy_pk());
        e0.recv_pn_range = Some((1, 10));
        entries.push_back(e0);

        let mut e1 = KeyEntry::new(1, dummy_pk(), dummy_pk());
        e1.recv_pn_range = None;
        entries.push_back(e1);

        let mut keys = test_keys_with_entries(entries);
        let err = keys
            .update_by_peer()
            .expect_err("must reject detect consecutive peer key update");
        assert_eq!(err.kind(), ErrorKind::KeyUpdate);
    }

    #[test]
    fn key_update_error_on_peer_unsynced_ack_using_old_key_phase() {
        let mut entries = VecDeque::new();
        entries.push_back(KeyEntry::new(0, dummy_pk(), dummy_pk()));
        entries.push_back(KeyEntry::new(1, dummy_pk(), dummy_pk()));
        let mut keys = test_keys_with_entries(entries);

        keys.sent_pk_stage.insert(42, 1);

        let err = keys
            .validate_ack(42, 42, Some(0))
            .expect_err("must reject old-key ACKing new-key packet");
        assert_eq!(err.kind(), ErrorKind::KeyUpdate);
    }

    #[test]
    fn key_update_error_on_key_downgrade_high_pn_decrypted_with_old_key() {
        let mut entries = VecDeque::new();
        let mut e0 = KeyEntry::new(0, dummy_pk(), dummy_pk());
        e0.recv_pn_range = Some((1, 50));
        entries.push_back(e0);

        let mut e1 = KeyEntry::new(1, dummy_pk(), dummy_pk());
        e1.recv_pn_range = Some((100, 120));
        entries.push_back(e1);

        let mut keys = test_keys_with_entries(entries);
        let err = keys
            .decrypted_packet(130, 0)
            .expect_err("must reject decrypting higher PN with old key");
        assert_eq!(err.kind(), ErrorKind::KeyUpdate);
    }
}
