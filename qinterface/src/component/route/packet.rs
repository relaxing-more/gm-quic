use bytes::{Bytes, BytesMut};
use derive_more::Deref;
use qbase::{
    error::QuicError,
    packet::{
        decrypt::{
            decrypt_packet, remove_protection_of_long_packet, remove_protection_of_short_packet,
        },
        header::long::InitialHeader,
        keys::ArcOneRttPacketKeys,
        number::{InvalidPacketNumber, PacketNumber},
    },
};
use qevent::quic::{
    PacketHeader, PacketHeaderBuilder, QuicFrame,
    transport::{PacketDropped, PacketDroppedTrigger, PacketReceived},
};
use rustls::quic::{HeaderProtectionKey, PacketKey};

#[derive(Debug, Deref)]
pub struct CipherPacket<H> {
    #[deref]
    header: H,
    payload: BytesMut,
    payload_offset: usize,
}

impl<H> CipherPacket<H>
where
    PacketHeaderBuilder: for<'a> From<&'a H>,
{
    pub fn new(header: H, payload: BytesMut, payload_offset: usize) -> Self {
        Self {
            header,
            payload,
            payload_offset,
        }
    }

    pub fn header(&self) -> &H {
        &self.header
    }

    fn qlog_header(&self) -> PacketHeader {
        PacketHeaderBuilder::from(&self.header).build()
    }

    pub fn drop_on_key_unavailable(self) {
        qevent::event!(PacketDropped {
            header: self.qlog_header(),
            raw: self.payload.freeze(),
            trigger: PacketDroppedTrigger::KeyUnavailable
        })
    }

    fn drop_on_remove_header_protection_failure(self) {
        qevent::event!(
            PacketDropped {
                header: self.qlog_header(),
                raw: self.payload.freeze(),
                trigger: PacketDroppedTrigger::DecryptionFailure
            },
            details = Map {
                reason: "remove header protection failure"
            }
        );
    }

    fn drop_on_decryption_failure(self, error: qbase::packet::error::Error, pn: u64) {
        qevent::event!(
            PacketDropped {
                header: {
                    PacketHeaderBuilder::from(&self.header)
                        .packet_number(pn)
                        .build()
                },
                raw: self.payload.freeze(),
                trigger: PacketDroppedTrigger::DecryptionFailure
            },
            details = Map {
                reason: "decryption failure",
                error: error.to_string(),
            },
        )
    }

    fn drop_on_reverse_bit_error(self, error: &qbase::packet::error::Error) {
        qevent::event!(
            PacketDropped {
                header: self.qlog_header(),
                raw: self.payload.freeze(),
                trigger: PacketDroppedTrigger::Invalid,
            },
            details = Map {
                reason: "reverse bit error",
                error: error.to_string()
            },
        )
    }

    fn drop_on_invalid_pn(self, invalid_pn: InvalidPacketNumber) {
        qevent::event!(
            PacketDropped {
                header: self.qlog_header(),
                raw: self.payload.freeze(),
                trigger: PacketDroppedTrigger::Invalid,
            },
            details = Map {
                reason: "invalid packet number",
                invalid_pn: invalid_pn.to_string()
            },
        )
    }

    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub fn decrypt_long_packet(
        mut self,
        hpk: &dyn HeaderProtectionKey,
        pk: &dyn PacketKey,
        pn_decoder: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
    ) -> Option<Result<PlainPacket<H>, QuicError>> {
        let pkt_buf = self.payload.as_mut();
        let undecoded_pn = match remove_protection_of_long_packet(hpk, pkt_buf, self.payload_offset)
        {
            Ok(Some(undecoded_pn)) => undecoded_pn,
            Ok(None) => {
                self.drop_on_remove_header_protection_failure();
                return None;
            }
            Err(invalid_reverse_bits) => {
                self.drop_on_reverse_bit_error(&invalid_reverse_bits);
                return Some(Err(invalid_reverse_bits.into()));
            }
        };
        let decoded_pn = match pn_decoder(undecoded_pn) {
            Ok(pn) => pn,
            Err(invalid_packet_number) => {
                self.drop_on_invalid_pn(invalid_packet_number);
                return None;
            }
        };
        let body_offset = self.payload_offset + undecoded_pn.size();
        let body_length = match decrypt_packet(pk, decoded_pn, pkt_buf, body_offset) {
            Ok(body_length) => body_length,
            Err(error) => {
                self.drop_on_decryption_failure(error, decoded_pn);
                return None;
            }
        };

        Some(Ok(PlainPacket {
            header: self.header,
            plain: self.payload.freeze(),
            payload_offset: self.payload_offset,
            undecoded_pn,
            decoded_pn,
            body_len: body_length,
            key_generation: None,
        }))
    }

    pub fn decrypt_short_packet(
        mut self,
        hpk: &dyn HeaderProtectionKey,
        pk: &ArcOneRttPacketKeys,
        pn_decoder: impl FnOnce(PacketNumber) -> Result<u64, InvalidPacketNumber>,
    ) -> Option<Result<PlainPacket<H>, QuicError>> {
        let pkt_buf = self.payload.as_mut();
        let (undecoded_pn, key_phase) =
            match remove_protection_of_short_packet(hpk, pkt_buf, self.payload_offset) {
                Ok(Some((undecoded, key_phase))) => (undecoded, key_phase),
                Ok(None) => {
                    self.drop_on_remove_header_protection_failure();
                    return None;
                }
                Err(invalid_reverse_bits) => {
                    self.drop_on_reverse_bit_error(&invalid_reverse_bits);
                    return Some(Err(invalid_reverse_bits.into()));
                }
            };
        let decoded_pn = match pn_decoder(undecoded_pn) {
            Ok(pn) => pn,
            Err(invalid_pn) => {
                self.drop_on_invalid_pn(invalid_pn);
                return None;
            }
        };
        let body_offset = self.payload_offset + undecoded_pn.size();

        // Try to get the appropriate key for this packet using pn + key_phase
        let (generation, key_opt) = {
            let keys = pk.lock_guard();
            match keys.get_remote_key(decoded_pn, key_phase) {
                Ok((generation, key)) => (Some(generation), key),
                Err(_) => (None, None),
            }
        };

        // Try decryption with the determined key
        if let Some(key) = key_opt {
            match decrypt_packet(key.as_ref(), decoded_pn, pkt_buf, body_offset) {
                Ok(body_length) => {
                    // Success: update recv_pk_ranges and return
                    if let Some(generation_val) = generation {
                        let mut keys = pk.lock_guard();
                        if let Err(e) = keys.on_pk_decrypted_success(generation_val, decoded_pn) {
                            return Some(Err(e));
                        }
                    }
                    return Some(Ok(PlainPacket {
                        header: self.header,
                        plain: self.payload.freeze(),
                        payload_offset: self.payload_offset,
                        undecoded_pn,
                        decoded_pn,
                        body_len: body_length,
                        key_generation: generation,
                    }));
                }
                Err(_) => {
                    // Record failure but continue to try alternatives
                    let should_abort = {
                        let mut keys = pk.lock_guard();
                        keys.on_pk_decrypt_failed()
                    };

                    if should_abort {
                        self.drop_on_decryption_failure(
                            qbase::packet::error::Error::DecryptPacketFailure,
                            decoded_pn,
                        );
                        return None;
                    }
                }
            }
        }

        // Fallback: if key was None or decryption failed, try candidate generations
        let (candidates, next_generation) = {
            let keys = pk.lock_guard();
            let mut candidates = Vec::with_capacity(2);
            let mut next_generation = None;

            for generation in keys.remote_key_candidates(key_phase).into_iter().flatten() {
                match keys.key(generation) {
                    Ok(Some(key)) => candidates.push((generation, key)),
                    Ok(None) => next_generation = Some(generation),
                    Err(_) => {}
                }
            }

            (candidates, next_generation)
        };

        for (generation, key) in candidates {
            match decrypt_packet(key.as_ref(), decoded_pn, pkt_buf, body_offset) {
                Ok(body_length) => {
                    // Success: update recv_pk_ranges
                    let mut keys = pk.lock_guard();
                    if let Err(e) = keys.on_pk_decrypted_success(generation, decoded_pn) {
                        return Some(Err(e));
                    }
                    drop(keys);

                    return Some(Ok(PlainPacket {
                        header: self.header,
                        plain: self.payload.freeze(),
                        payload_offset: self.payload_offset,
                        undecoded_pn,
                        decoded_pn,
                        body_len: body_length,
                        key_generation: Some(generation),
                    }));
                }
                Err(_) => {
                    let should_abort = {
                        let mut keys = pk.lock_guard();
                        keys.on_pk_decrypt_failed()
                    };

                    if should_abort {
                        self.drop_on_decryption_failure(
                            qbase::packet::error::Error::DecryptPacketFailure,
                            decoded_pn,
                        );
                        return None;
                    }
                }
            }
        }

        // Try the next generation if needed
        if let Some(generation) = next_generation {
            let next_key = {
                let mut keys = pk.lock_guard();
                if matches!(keys.key(generation), Ok(None)) {
                    if let Err(e) = keys.update_by_peer() {
                        return Some(Err(e));
                    }
                }
                keys.key(generation).ok().flatten()
            };

            if let Some(key) = next_key {
                match decrypt_packet(key.as_ref(), decoded_pn, pkt_buf, body_offset) {
                    Ok(body_length) => {
                        let mut keys = pk.lock_guard();
                        if let Err(e) = keys.on_pk_decrypted_success(generation, decoded_pn) {
                            return Some(Err(e));
                        }
                        drop(keys);

                        return Some(Ok(PlainPacket {
                            header: self.header,
                            plain: self.payload.freeze(),
                            payload_offset: self.payload_offset,
                            undecoded_pn,
                            decoded_pn,
                            body_len: body_length,
                            key_generation: Some(generation),
                        }));
                    }
                    Err(_) => {
                        let should_abort = {
                            let mut keys = pk.lock_guard();
                            keys.on_pk_decrypt_failed()
                        };

                        if should_abort {
                            self.drop_on_decryption_failure(
                                qbase::packet::error::Error::DecryptPacketFailure,
                                decoded_pn,
                            );
                            return None;
                        }
                    }
                }
            }
        }

        // All decryption attempts failed
        self.drop_on_decryption_failure(
            qbase::packet::error::Error::DecryptPacketFailure,
            decoded_pn,
        );
        None
    }
}

impl CipherPacket<InitialHeader> {
    pub fn drop_on_scid_unmatch(self) {
        qevent::event!(
            PacketDropped {
                header: self.qlog_header(),
                raw: self.payload.freeze(),
                trigger: PacketDroppedTrigger::Rejected
            },
            details = Map {
                reason: "different scid with first initial packet"
            },
        )
    }
}

#[derive(Deref)]
pub struct PlainPacket<H> {
    #[deref]
    header: H,
    decoded_pn: u64,
    undecoded_pn: PacketNumber,
    plain: Bytes,
    payload_offset: usize,
    body_len: usize,
    key_generation: Option<u64>,
}

impl<H> PlainPacket<H> {
    pub fn size(&self) -> usize {
        self.plain.len()
    }

    pub fn pn(&self) -> u64 {
        self.decoded_pn
    }

    pub fn payload_len(&self) -> usize {
        self.undecoded_pn.size() + self.body_len
    }

    pub fn key_generation(&self) -> Option<u64> {
        self.key_generation
    }

    pub fn body(&self) -> Bytes {
        let packet_offset = self.payload_offset + self.undecoded_pn.size();
        self.plain
            .slice(packet_offset..packet_offset + self.body_len)
    }

    pub fn raw_info(&self) -> qevent::RawInfo {
        qevent::build!(qevent::RawInfo {
            length: self.plain.len() as u64,
            payload_length: self.payload_len() as u64,
            data: &self.plain,
        })
    }
}

impl<H> PlainPacket<H>
where
    PacketHeaderBuilder: for<'a> From<&'a H>,
{
    pub fn qlog_header(&self) -> PacketHeader {
        let mut builder = PacketHeaderBuilder::from(&self.header);
        qevent::build! {@field builder,
            packet_number: self.decoded_pn,
            length: self.payload_len() as u16
        };
        builder.build()
    }

    pub fn drop_on_interface_not_found(self) {
        qevent::event!(
            PacketDropped {
                header: self.qlog_header(),
                raw: self.raw_info(),
                trigger: PacketDroppedTrigger::Genera
            },
            details = Map {
                reason: "interface not found"
            }
        )
    }

    pub fn drop_on_conenction_closed(self) {
        qevent::event!(
            PacketDropped {
                header: self.qlog_header(),
                raw: self.raw_info(),
                trigger: PacketDroppedTrigger::Genera
            },
            details = Map {
                reason: "connection closed"
            }
        )
    }

    pub fn log_received(&self, frames: impl Into<Vec<QuicFrame>>) {
        qevent::event!(PacketReceived {
            header: self.qlog_header(),
            frames,
            raw: self.raw_info(),
        })
    }
}
