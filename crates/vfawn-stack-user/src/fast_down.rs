// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: Copyright (c) 2026 VFawn contributors

//! The downlink fast path: frames for an established relay flow are
//! built here and pushed straight into the TUN's write channel,
//! skipping the write lane, the shard's drain, and the writer's batch
//! assembly. The relay task calls [`push_downlink`] with the payload
//! it just read from the outbound socket; the answer is whether the
//! frames left (false means fall back to the session write).

use bytes::BytesMut;

/// Build and push TCP data frames for one downlink write. The payload
/// is split into MSS-sized segments, each framed with the flow's
/// addresses and the given sequence base (advanced per segment). The
/// acknowledgment and window come from the caller's current view of
/// the connection; the checksum is computed over the pseudo header.
/// Everything the frame builder needs per call.
pub struct DownlinkContext<'a> {
    pub lane: &'a crate::splice_lane::SpliceLane,
    pub src: std::net::SocketAddrV4,
    pub dst: std::net::SocketAddrV4,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub mss: u16,
}

pub fn push_downlink(ctx: &DownlinkContext, payload: &[u8]) -> bool {
    if payload.is_empty() {
        return true;
    }
    let mss = ctx.mss as usize;
    let segments = payload.len().div_ceil(mss);
    let mut frames = Vec::with_capacity(segments);
    let mut offset = 0usize;
    let mut seq = ctx.seq;
    while offset < payload.len() {
        let take = (payload.len() - offset).min(mss);
        let more_after = offset + take < payload.len();
        let reaction = crate::native_tcp::Reaction {
            seq,
            ack: ctx.ack,
            flags: if more_after { 0x10 } else { 0x18 },
            window: ctx.window,
            delivered: Vec::new(),
            held: false,
            gap_filled: false,
        };
        let frame = crate::native_tcp::emit_v4(
            ctx.src,
            ctx.dst,
            &reaction,
            &[],
            &payload[offset..offset + take],
        );
        frames.push(BytesMut::from(&frame[..]));
        seq = seq.wrapping_add(take as u32);
        offset += take;
    }
    ctx.lane.try_push_to_tun(frames).is_ok()
}
