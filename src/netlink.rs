use crate::config::*;
use anyhow::{anyhow, bail, Context, Result};
use bytes::BytesMut;
use netlink_sys::{protocols::NETLINK_GENERIC, Socket, SocketAddr};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// --- Raw reply parsing structs ---

#[repr(C)]
#[derive(Clone, Copy)]
struct NlmsghdrRaw {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct GenlmsghdrRaw {
    cmd: u8,
    version: u8,
    reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlattrRaw {
    nla_len: u16,
    nla_type: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlmsgerrRaw {
    error: i32,
    msg: NlmsghdrRaw,
}

// --- Socket wrapper ---

struct NetlinkSocket {
    socket: Socket,
    seq: u32,
    pid: u32,
}

impl NetlinkSocket {
    fn connect() -> Result<Self> {
        let mut socket = Socket::new(NETLINK_GENERIC).context("socket(NETLINK_GENERIC) failed")?;
        socket.bind_auto().context("bind_auto() failed")?;

        Ok(Self {
            socket,
            seq: 1,
            pid: 0,
        })
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    fn send(&mut self, buf: &[u8]) -> Result<()> {
        let kernel = SocketAddr::new(0, 0);
        self.socket
            .send_to(buf, &kernel, 0)
            .context("netlink send_to failed")?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(65536);
        let (size, _addr) = self
            .socket
            .recv_from(&mut buf, 0)
            .context("netlink recv_from failed")?;
        Ok(buf[..size].to_vec())
    }
}

// --- Byte helpers ---

fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(bytes);
}

fn push_nlattr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let start = buf.len();
    let hdr = NlattrRaw {
        nla_len: (size_of::<NlattrRaw>() + payload.len()) as u16,
        nla_type: attr_type,
    };
    let hdr_bytes = unsafe {
        std::slice::from_raw_parts(
            (&hdr as *const NlattrRaw) as *const u8,
            size_of::<NlattrRaw>(),
        )
    };
    push_bytes(buf, hdr_bytes);
    push_bytes(buf, payload);

    let aligned = nla_align(buf.len() - start);
    let pad = aligned - (buf.len() - start);
    if pad > 0 {
        buf.resize(buf.len() + pad, 0);
    }
}

fn build_packet_genl_msg(
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
    cmd: u8,
    version: u8,
    attrs: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let mut attrs_buf = Vec::new();
    for (t, p) in attrs {
        push_nlattr(&mut attrs_buf, *t, p);
    }

    let total_len = size_of::<NlmsghdrRaw>() + size_of::<GenlmsghdrRaw>() + attrs_buf.len();

    let mut buf = Vec::with_capacity(total_len);

    // nlmsghdr
    buf.extend_from_slice(&(total_len as u32).to_ne_bytes());
    buf.extend_from_slice(&nlmsg_type.to_ne_bytes());
    buf.extend_from_slice(&nlmsg_flags.to_ne_bytes());
    buf.extend_from_slice(&nlmsg_seq.to_ne_bytes());
    buf.extend_from_slice(&nlmsg_pid.to_ne_bytes());

    // genlmsghdr
    buf.push(cmd);
    buf.push(version);
    buf.extend_from_slice(&0u16.to_ne_bytes());

    // attrs
    buf.extend_from_slice(&attrs_buf);

    buf
}

// --- Raw reply parsing helpers ---

fn parse_nlmsghdr(buf: &[u8], offset: usize) -> Option<NlmsghdrRaw> {
    if offset + size_of::<NlmsghdrRaw>() > buf.len() {
        return None;
    }
    let ptr = unsafe { buf.as_ptr().add(offset) as *const NlmsghdrRaw };
    Some(unsafe { std::ptr::read_unaligned(ptr) })
}

fn parse_genlhdr(buf: &[u8], offset: usize) -> Option<GenlmsghdrRaw> {
    if offset + size_of::<GenlmsghdrRaw>() > buf.len() {
        return None;
    }
    let ptr = unsafe { buf.as_ptr().add(offset) as *const GenlmsghdrRaw };
    Some(unsafe { std::ptr::read_unaligned(ptr) })
}

fn parse_attrs(mut data: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while data.len() >= size_of::<NlattrRaw>() {
        let hdr = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const NlattrRaw) };
        let nla_len = hdr.nla_len as usize;
        if nla_len < size_of::<NlattrRaw>() || nla_len > data.len() {
            break;
        }
        let payload = &data[size_of::<NlattrRaw>()..nla_len];
        out.push((hdr.nla_type, payload));
        let step = nla_align(nla_len);
        if step > data.len() {
            break;
        }
        data = &data[step..];
    }
    out
}

pub fn check_nlmsg_error(payload: &[u8]) -> Result<()> {
    if payload.len() < size_of::<NlmsgerrRaw>() {
        bail!("short NLMSG_ERROR payload");
    }
    let err = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const NlmsgerrRaw) };
    if err.error == 0 {
        return Ok(());
    }
    let errno = -err.error;
    Err(std::io::Error::from_raw_os_error(errno)).context("netlink error")
}

// --- Generic netlink helpers ---

fn resolve_genl_family_id(sock: &mut NetlinkSocket, family_name: &str) -> Result<u16> {
    let seq = sock.next_seq();
    let mut name = family_name.as_bytes().to_vec();
    name.push(0);

    let msg = build_packet_genl_msg(
        GENL_ID_CTRL,
        NLM_F_REQUEST,
        seq,
        sock.pid,
        CTRL_CMD_GETFAMILY,
        1,
        &[(CTRL_ATTR_FAMILY_NAME, name)],
    );

    sock.send(&msg)?;

    loop {
        let rx = sock.recv()?;
        let mut off = 0usize;

        while off + size_of::<NlmsghdrRaw>() <= rx.len() {
            let nlh = parse_nlmsghdr(&rx, off).ok_or_else(|| anyhow!("bad nlmsghdr"))?;
            if (nlh.nlmsg_len as usize) < size_of::<NlmsghdrRaw>() {
                bail!("invalid nlmsg_len");
            }

            let msg_end = off + (nlh.nlmsg_len as usize);
            if msg_end > rx.len() {
                bail!("truncated netlink message");
            }

            if nlh.nlmsg_seq != seq {
                off += nlmsg_align(nlh.nlmsg_len as usize);
                continue;
            }

            match nlh.nlmsg_type {
                NLMSG_ERROR => {
                    let payload = &rx[off + size_of::<NlmsghdrRaw>()..msg_end];
                    check_nlmsg_error(payload)?;
                }
                NLMSG_DONE => bail!("generic netlink family not found"),
                _ => {
                    let genl_off = off + size_of::<NlmsghdrRaw>();
                    let _genlh =
                        parse_genlhdr(&rx, genl_off).ok_or_else(|| anyhow!("bad genlhdr"))?;
                    let attrs_off = genl_off + size_of::<GenlmsghdrRaw>();
                    let attrs = parse_attrs(&rx[attrs_off..msg_end]);
                    for (ty, payload) in attrs {
                        if ty == CTRL_ATTR_FAMILY_ID && payload.len() >= 2 {
                            let id = u16::from_ne_bytes([payload[0], payload[1]]);
                            return Ok(id);
                        }
                    }
                }
            }

            off += nlmsg_align(nlh.nlmsg_len as usize);
        }
    }
}

fn get_connection() -> Result<(NetlinkSocket, u16)> {
    let mut socket = NetlinkSocket::connect()?;
    let family_id = resolve_genl_family_id(&mut socket, TUTU_GENL_FAMILY_NAME)?;
    Ok((socket, family_id))
}

pub fn send_struct<T: IntoBytes + Immutable + ?Sized>(
    cmd: u8,
    attr_type: u16,
    data: &T,
    ack: bool,
) -> Result<()> {
    let (mut socket, family_id) = get_connection()?;
    let seq = socket.next_seq();
    let payload = data.as_bytes().to_vec();

    let flags = if ack {
        NLM_F_REQUEST | NLM_F_ACK
    } else {
        NLM_F_REQUEST
    };

    let msg = build_packet_genl_msg(
        family_id,
        flags,
        seq,
        socket.pid,
        cmd,
        TUTU_GENL_VERSION,
        &[(attr_type, payload)],
    );

    socket.send(&msg)?;

    if ack {
        loop {
            let rx = socket.recv()?;
            let mut off = 0usize;
            while off + size_of::<NlmsghdrRaw>() <= rx.len() {
                let nlh = parse_nlmsghdr(&rx, off).ok_or_else(|| anyhow!("bad nlmsghdr"))?;
                if (nlh.nlmsg_len as usize) < size_of::<NlmsghdrRaw>() {
                    bail!("invalid nlmsg_len");
                }
                let msg_end = off + (nlh.nlmsg_len as usize);
                if msg_end > rx.len() {
                    bail!("truncated netlink message");
                }

                if nlh.nlmsg_seq != seq {
                    off += nlmsg_align(nlh.nlmsg_len as usize);
                    continue;
                }

                match nlh.nlmsg_type {
                    NLMSG_ERROR => {
                        let payload = &rx[off + size_of::<NlmsghdrRaw>()..msg_end];
                        check_nlmsg_error(payload)?;
                        return Ok(());
                    }
                    NLMSG_DONE => return Ok(()),
                    _ => {}
                }

                off += nlmsg_align(nlh.nlmsg_len as usize);
            }
        }
    }

    Ok(())
}

pub fn send_string(cmd: u8, attr_type: u16, data: &str, ack: bool) -> Result<()> {
    let (mut socket, family_id) = get_connection()?;
    let seq = socket.next_seq();

    let mut vec_data = data.as_bytes().to_vec();
    vec_data.push(0);

    let flags = if ack {
        NLM_F_REQUEST | NLM_F_ACK
    } else {
        NLM_F_REQUEST
    };

    let msg = build_packet_genl_msg(
        family_id,
        flags,
        seq,
        socket.pid,
        cmd,
        TUTU_GENL_VERSION,
        &[(attr_type, vec_data)],
    );

    socket.send(&msg)?;

    if ack {
        loop {
            let rx = socket.recv()?;
            let mut off = 0usize;
            while off + size_of::<NlmsghdrRaw>() <= rx.len() {
                let nlh = parse_nlmsghdr(&rx, off).ok_or_else(|| anyhow!("bad nlmsghdr"))?;
                if (nlh.nlmsg_len as usize) < size_of::<NlmsghdrRaw>() {
                    bail!("invalid nlmsg_len");
                }
                let msg_end = off + (nlh.nlmsg_len as usize);
                if msg_end > rx.len() {
                    bail!("truncated netlink message");
                }

                if nlh.nlmsg_seq != seq {
                    off += nlmsg_align(nlh.nlmsg_len as usize);
                    continue;
                }

                match nlh.nlmsg_type {
                    NLMSG_ERROR => {
                        let payload = &rx[off + size_of::<NlmsghdrRaw>()..msg_end];
                        check_nlmsg_error(payload)?;
                        return Ok(());
                    }
                    NLMSG_DONE => return Ok(()),
                    _ => {}
                }

                off += nlmsg_align(nlh.nlmsg_len as usize);
            }
        }
    }

    Ok(())
}

pub fn receive_struct<T: FromBytes + Immutable>(
    cmd: u8,
    attr_type: u16,
    in_data: Option<&[u8]>,
) -> Result<T> {
    let (mut socket, family_id) = get_connection()?;
    let seq = socket.next_seq();

    let attrs = match in_data {
        Some(d) => vec![(attr_type, d.to_vec())],
        None => Vec::new(),
    };

    let msg = build_packet_genl_msg(
        family_id,
        NLM_F_REQUEST,
        seq,
        socket.pid,
        cmd,
        TUTU_GENL_VERSION,
        &attrs,
    );

    socket.send(&msg)?;

    loop {
        let rx = socket.recv()?;
        let mut off = 0usize;

        while off + size_of::<NlmsghdrRaw>() <= rx.len() {
            let nlh = parse_nlmsghdr(&rx, off).ok_or_else(|| anyhow!("bad nlmsghdr"))?;
            if (nlh.nlmsg_len as usize) < size_of::<NlmsghdrRaw>() {
                bail!("invalid nlmsg_len");
            }
            let msg_end = off + (nlh.nlmsg_len as usize);
            if msg_end > rx.len() {
                bail!("truncated netlink message");
            }

            if nlh.nlmsg_seq != seq {
                off += nlmsg_align(nlh.nlmsg_len as usize);
                continue;
            }

            match nlh.nlmsg_type {
                NLMSG_ERROR => {
                    let payload = &rx[off + size_of::<NlmsghdrRaw>()..msg_end];
                    check_nlmsg_error(payload)?;
                }
                NLMSG_DONE => bail!("no response"),
                _ => {
                    let genl_off = off + size_of::<NlmsghdrRaw>();
                    let _genlh =
                        parse_genlhdr(&rx, genl_off).ok_or_else(|| anyhow!("bad genlhdr"))?;
                    let attrs_off = genl_off + size_of::<GenlmsghdrRaw>();
                    let attrs = parse_attrs(&rx[attrs_off..msg_end]);

                    for (ty, payload) in attrs {
                        if ty == attr_type {
                            if payload.len() < size_of::<T>() {
                                bail!("received data too small for struct");
                            }
                            let parsed = T::read_from_prefix(payload)
                                .map_err(|_| anyhow!("failed to parse struct"))?;
                            return Ok(parsed.0);
                        }
                    }
                }
            }

            off += nlmsg_align(nlh.nlmsg_len as usize);
        }
    }
}

pub fn dump_structs<T: FromBytes + Immutable>(
    cmd: u8,
    attr_type: u16,
    mut handler: impl FnMut(&T) -> Result<()>,
) -> Result<()> {
    let (mut socket, family_id) = get_connection()?;
    let seq = socket.next_seq();

    let msg = build_packet_genl_msg(
        family_id,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        socket.pid,
        cmd,
        TUTU_GENL_VERSION,
        &[],
    );

    socket.send(&msg)?;

    loop {
        let rx = socket.recv()?;
        let mut off = 0usize;

        while off + size_of::<NlmsghdrRaw>() <= rx.len() {
            let nlh = parse_nlmsghdr(&rx, off).ok_or_else(|| anyhow!("bad nlmsghdr"))?;
            if (nlh.nlmsg_len as usize) < size_of::<NlmsghdrRaw>() {
                bail!("invalid nlmsg_len");
            }
            let msg_end = off + (nlh.nlmsg_len as usize);
            if msg_end > rx.len() {
                bail!("truncated netlink message");
            }

            if nlh.nlmsg_seq != seq {
                off += nlmsg_align(nlh.nlmsg_len as usize);
                continue;
            }

            match nlh.nlmsg_type {
                NLMSG_DONE => return Ok(()),
                NLMSG_ERROR => {
                    let payload = &rx[off + size_of::<NlmsghdrRaw>()..msg_end];
                    check_nlmsg_error(payload)?;
                }
                _ => {
                    let genl_off = off + size_of::<NlmsghdrRaw>();
                    let _genlh =
                        parse_genlhdr(&rx, genl_off).ok_or_else(|| anyhow!("bad genlhdr"))?;
                    let attrs_off = genl_off + size_of::<GenlmsghdrRaw>();
                    let attrs = parse_attrs(&rx[attrs_off..msg_end]);

                    for (ty, payload) in attrs {
                        if ty == attr_type {
                            if let Ok((val, _)) = T::read_from_prefix(payload) {
                                handler(&val)?;
                            }
                        }
                    }
                }
            }

            off += nlmsg_align(nlh.nlmsg_len as usize);
        }
    }
}

pub fn dump_strings(
    cmd: u8,
    attr_type: u16,
    mut handler: impl FnMut(String) -> Result<()>,
) -> Result<()> {
    let (mut socket, family_id) = get_connection()?;
    let seq = socket.next_seq();

    let msg = build_packet_genl_msg(
        family_id,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        socket.pid,
        cmd,
        TUTU_GENL_VERSION,
        &[],
    );

    socket.send(&msg)?;

    loop {
        let rx = socket.recv()?;
        let mut off = 0usize;

        while off + size_of::<NlmsghdrRaw>() <= rx.len() {
            let nlh = parse_nlmsghdr(&rx, off).ok_or_else(|| anyhow!("bad nlmsghdr"))?;
            if (nlh.nlmsg_len as usize) < size_of::<NlmsghdrRaw>() {
                bail!("invalid nlmsg_len");
            }
            let msg_end = off + (nlh.nlmsg_len as usize);
            if msg_end > rx.len() {
                bail!("truncated netlink message");
            }

            if nlh.nlmsg_seq != seq {
                off += nlmsg_align(nlh.nlmsg_len as usize);
                continue;
            }

            match nlh.nlmsg_type {
                NLMSG_DONE => return Ok(()),
                NLMSG_ERROR => {
                    let payload = &rx[off + size_of::<NlmsghdrRaw>()..msg_end];
                    check_nlmsg_error(payload)?;
                }
                _ => {
                    let genl_off = off + size_of::<NlmsghdrRaw>();
                    let _genlh =
                        parse_genlhdr(&rx, genl_off).ok_or_else(|| anyhow!("bad genlhdr"))?;
                    let attrs_off = genl_off + size_of::<GenlmsghdrRaw>();
                    let attrs = parse_attrs(&rx[attrs_off..msg_end]);

                    for (ty, payload) in attrs {
                        if ty == attr_type {
                            let len = payload
                                .iter()
                                .position(|&c| c == 0)
                                .unwrap_or(payload.len());
                            let s = String::from_utf8_lossy(&payload[..len]).to_string();
                            handler(s)?;
                        }
                    }
                }
            }

            off += nlmsg_align(nlh.nlmsg_len as usize);
        }
    }
}

fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

fn nla_align(len: usize) -> usize {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}
