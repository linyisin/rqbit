// Added by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-22: NAT-PMP port mapping
// (RFC 6886), qBittorrent's "Use UPnP / NAT-PMP port forwarding from my router". Licensed under
// Apache-2.0 like the rest of rqbit.
//
// The wire format is RFC 6886's. The timing follows libtorrent's src/natpmp.cpp: a 3600 s lease
// (natpmp_lease_duration), renewal after 3/4 of the granted lifetime, linear retransmission
// (250 ms × attempt, 9 attempts), one request at a time, and a new try two hours after a mapping
// failed. libtorrent's copyright notice:
//
// Copyright (c) 2007-2022, Arvid Norberg
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the distribution.
//     * Neither the name of the author nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use tokio::{net::UdpSocket, time::Instant};
use tracing::{debug, info, warn};

/// The port NAT-PMP gateways listen on.
pub const NATPMP_PORT: u16 = 5351;
const VERSION: u8 = 0;
const OP_EXTERNAL_ADDRESS: u8 = 0;
const RESPONSE: u8 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Udp = 1,
    Tcp = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub protocol: Protocol,
    pub internal_port: u16,
    pub external_port: u16,
    /// Seconds; 0 when a mapping was removed.
    pub lifetime: u32,
}

#[derive(thiserror::Error, Debug)]
pub enum NatPmpError {
    #[error("the gateway did not answer (it may not support NAT-PMP)")]
    NoAnswer,
    #[error("the gateway refused: {}", result_text(*.0))]
    Refused(u16),
    #[error("malformed answer from the gateway")]
    Malformed,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// RFC 6886 section 3.5 result codes.
fn result_text(code: u16) -> &'static str {
    match code {
        1 => "unsupported version",
        2 => "not authorized (NAT-PMP may be turned off on the router)",
        3 => "network failure",
        4 => "out of resources",
        5 => "unsupported opcode",
        _ => "unknown result code",
    }
}

pub(crate) fn encode_map_request(protocol: Protocol, internal_port: u16, external_port: u16, lifetime: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = VERSION;
    b[1] = protocol as u8;
    // b[2..4]: reserved
    b[4..6].copy_from_slice(&internal_port.to_be_bytes());
    b[6..8].copy_from_slice(&external_port.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime.to_be_bytes());
    b
}

/// The result code of an answer to `op`, or `None` if the packet isn't one.
fn check_header(buf: &[u8], op: u8) -> Result<Option<()>, NatPmpError> {
    if buf.len() < 4 || buf[0] != VERSION || buf[1] != RESPONSE + op {
        return Ok(None);
    }
    match u16::from_be_bytes([buf[2], buf[3]]) {
        0 => Ok(Some(())),
        code => Err(NatPmpError::Refused(code)),
    }
}

/// Parses the answer to an external address request; `None` for unrelated packets.
pub(crate) fn parse_external_address(buf: &[u8]) -> Result<Option<Ipv4Addr>, NatPmpError> {
    if check_header(buf, OP_EXTERNAL_ADDRESS)?.is_none() {
        return Ok(None);
    }
    let ip: [u8; 4] = buf.get(8..12).ok_or(NatPmpError::Malformed)?.try_into().unwrap();
    Ok(Some(Ipv4Addr::from(ip)))
}

/// Parses the answer to a mapping request for `protocol` / `internal_port`; `None` for unrelated
/// packets (e.g. a late answer to an earlier request).
pub(crate) fn parse_map_response(
    buf: &[u8],
    protocol: Protocol,
    internal_port: u16,
) -> Result<Option<Mapping>, NatPmpError> {
    if check_header(buf, protocol as u8)?.is_none() {
        return Ok(None);
    }
    if buf.len() < 16 {
        return Err(NatPmpError::Malformed);
    }
    let port = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]);
    if port(8) != internal_port {
        return Ok(None);
    }
    Ok(Some(Mapping {
        protocol,
        internal_port,
        external_port: port(10),
        lifetime: u32::from_be_bytes(buf[12..16].try_into().unwrap()),
    }))
}

/// Talks to one gateway, one request at a time.
pub(crate) struct Client {
    sock: UdpSocket,
    /// Retransmission n waits n × this (libtorrent: 250 ms).
    retry_unit: Duration,
    attempts: u32,
}

impl Client {
    pub async fn new(gateway: SocketAddr) -> std::io::Result<Self> {
        let bind: SocketAddr = match gateway.ip() {
            IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            IpAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let sock = UdpSocket::bind(bind).await?;
        // Connected: only the gateway's answers are received (RFC 6886 section 3.1).
        sock.connect(gateway).await?;
        Ok(Self { sock, retry_unit: Duration::from_millis(250), attempts: 9 })
    }

    #[cfg(test)]
    fn with_retry(mut self, unit: Duration, attempts: u32) -> Self {
        self.retry_unit = unit;
        self.attempts = attempts;
        self
    }

    async fn transact<T>(
        &self,
        request: &[u8],
        parse: impl Fn(&[u8]) -> Result<Option<T>, NatPmpError>,
    ) -> Result<T, NatPmpError> {
        let mut buf = [0u8; 64];
        for attempt in 1..=self.attempts {
            self.sock.send(request).await?;
            let deadline = Instant::now() + self.retry_unit * attempt;
            loop {
                let len = match tokio::time::timeout_at(deadline, self.sock.recv(&mut buf)).await {
                    Err(_) => break,
                    // E.g. ICMP port unreachable: nobody listens on the gateway's port.
                    Ok(Err(e)) => {
                        debug!("NAT-PMP receive error: {e}");
                        tokio::time::sleep_until(deadline).await;
                        break;
                    }
                    Ok(Ok(len)) => len,
                };
                if let Some(v) = parse(&buf[..len])? {
                    return Ok(v);
                }
            }
        }
        Err(NatPmpError::NoAnswer)
    }

    pub async fn external_address(&self) -> Result<Ipv4Addr, NatPmpError> {
        self.transact(&[VERSION, OP_EXTERNAL_ADDRESS], parse_external_address).await
    }

    /// Maps `port` to the same external port for `lifetime` seconds (0 removes it).
    pub async fn map(&self, protocol: Protocol, port: u16, lifetime: u32) -> Result<Mapping, NatPmpError> {
        let request = encode_map_request(protocol, port, port, lifetime);
        self.transact(&request, |b| parse_map_response(b, protocol, port)).await
    }
}

/// How long a mapping is asked for (libtorrent's natpmp_lease_duration).
pub(crate) const LEASE: Duration = Duration::from_secs(3600);
/// After a failure, try again this much later (libtorrent).
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(2 * 3600);

/// Keeps TCP and UDP mappings of `ports` alive at `gateway` until cancelled. `on_external_ip` gets
/// the public address the gateway reports.
pub(crate) async fn run_forever(
    gateway: SocketAddr,
    ports: Vec<u16>,
    lease: Duration,
    on_external_ip: impl Fn(Ipv4Addr),
) -> anyhow::Result<()> {
    run_with_client(Client::new(gateway).await?, gateway, ports, lease, on_external_ip).await
}

async fn run_with_client(
    client: Client,
    gateway: SocketAddr,
    ports: Vec<u16>,
    lease: Duration,
    on_external_ip: impl Fn(Ipv4Addr),
) -> anyhow::Result<()> {
    let lease_secs = u32::try_from(lease.as_secs()).unwrap_or(u32::MAX);
    match client.external_address().await {
        Ok(ip) => {
            info!(%gateway, external_ip = %ip, "NAT-PMP gateway found");
            on_external_ip(ip);
        }
        Err(e) => warn!(%gateway, "NAT-PMP: {e}"),
    }
    let mut due: Vec<(Protocol, u16, Instant)> = ports
        .iter()
        .flat_map(|&p| [(Protocol::Tcp, p, Instant::now()), (Protocol::Udp, p, Instant::now())])
        .collect();
    loop {
        for (protocol, port, when) in due.iter_mut() {
            if *when > Instant::now() {
                continue;
            }
            *when = match client.map(*protocol, *port, lease_secs).await {
                Ok(m) if m.lifetime > 0 => {
                    if m.external_port == m.internal_port {
                        info!(?protocol, port, lifetime = m.lifetime, "NAT-PMP port mapped");
                    } else {
                        warn!(?protocol, port, external_port = m.external_port, "NAT-PMP mapped a different external port");
                    }
                    Instant::now() + Duration::from_secs(u64::from(m.lifetime) * 3 / 4)
                }
                Ok(_) => Instant::now() + RETRY_AFTER_FAILURE,
                Err(e) => {
                    warn!(?protocol, port, "NAT-PMP port mapping failed: {e}");
                    Instant::now() + RETRY_AFTER_FAILURE
                }
            };
        }
        let next = due.iter().map(|d| d.2).min().unwrap_or_else(|| Instant::now() + LEASE);
        tokio::time::sleep_until(next).await;
    }
}

/// The IPv4 default gateway's NAT-PMP address.
pub(crate) fn default_gateway() -> anyhow::Result<SocketAddr> {
    let gw = netdev::get_default_gateway().map_err(|e| anyhow::anyhow!("no default gateway: {e}"))?;
    let ip = gw.ipv4.first().copied().ok_or_else(|| anyhow::anyhow!("the default gateway has no IPv4 address"))?;
    Ok((ip, NATPMP_PORT).into())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn test_codec() {
        assert_eq!(
            encode_map_request(Protocol::Tcp, 6881, 6881, 3600),
            [0, 2, 0, 0, 0x1a, 0xe1, 0x1a, 0xe1, 0, 0, 0x0e, 0x10]
        );
        let ext = [0, 128, 0, 0, 0, 0, 0, 9, 203, 0, 113, 7];
        assert_eq!(parse_external_address(&ext).unwrap(), Some(Ipv4Addr::new(203, 0, 113, 7)));
        // An answer to a different request is not ours.
        assert_eq!(parse_external_address(&[0, 129, 0, 0]).unwrap(), None);

        let map = [0, 130, 0, 0, 0, 0, 0, 9, 0x1a, 0xe1, 0x1a, 0xe2, 0, 0, 0x0e, 0x10];
        let m = parse_map_response(&map, Protocol::Tcp, 6881).unwrap().unwrap();
        assert_eq!((m.external_port, m.lifetime), (6882, 3600));
        assert_eq!(parse_map_response(&map, Protocol::Udp, 6881).unwrap(), None);
        assert_eq!(parse_map_response(&map, Protocol::Tcp, 6000).unwrap(), None);
        assert!(matches!(parse_map_response(&map[..12], Protocol::Tcp, 6881), Err(NatPmpError::Malformed)));
        let refused = [0, 130, 0, 2, 0, 0, 0, 9, 0x1a, 0xe1, 0, 0, 0, 0, 0, 0];
        let err = parse_map_response(&refused, Protocol::Tcp, 6881).unwrap_err();
        assert!(matches!(err, NatPmpError::Refused(2)));
        assert!(err.to_string().contains("not authorized"));
    }

    /// A NAT-PMP gateway on 127.0.0.1 that records requests and drops the first `drop` ones.
    struct FakeGateway {
        addr: SocketAddr,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    async fn fake_gateway(drop: usize, result: u16) -> FakeGateway {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let (len, from) = sock.recv_from(&mut buf).await.unwrap();
                let req = buf[..len].to_vec();
                let n = {
                    let mut r = seen.lock().unwrap();
                    r.push(req.clone());
                    r.len()
                };
                if n <= drop {
                    continue;
                }
                let mut out = vec![0, RESPONSE + req[1]];
                out.extend_from_slice(&result.to_be_bytes());
                out.extend_from_slice(&42u32.to_be_bytes()); // seconds since epoch
                if req[1] == OP_EXTERNAL_ADDRESS {
                    out.extend_from_slice(&[203, 0, 113, 7]);
                } else {
                    out.extend_from_slice(&req[4..6]); // internal port
                    out.extend_from_slice(&req[6..8]); // external port as asked
                    out.extend_from_slice(&req[8..12]); // lifetime as asked
                }
                sock.send_to(&out, from).await.unwrap();
            }
        });
        FakeGateway { addr, requests }
    }

    #[tokio::test]
    async fn test_client_retransmits() {
        let gw = fake_gateway(2, 0).await;
        let client = Client::new(gw.addr).await.unwrap().with_retry(Duration::from_millis(20), 9);
        assert_eq!(client.external_address().await.unwrap(), Ipv4Addr::new(203, 0, 113, 7));
        // Dropped twice, answered the third time.
        assert_eq!(gw.requests.lock().unwrap().len(), 3);
        let m = client.map(Protocol::Udp, 51413, 3600).await.unwrap();
        assert_eq!(m, Mapping { protocol: Protocol::Udp, internal_port: 51413, external_port: 51413, lifetime: 3600 });
        assert_eq!(gw.requests.lock().unwrap()[3], encode_map_request(Protocol::Udp, 51413, 51413, 3600));
    }

    #[tokio::test]
    async fn test_client_errors() {
        let gw = fake_gateway(0, 2).await;
        let client = Client::new(gw.addr).await.unwrap().with_retry(Duration::from_millis(20), 3);
        assert!(matches!(client.map(Protocol::Tcp, 1, 60).await, Err(NatPmpError::Refused(2))));

        let silent = fake_gateway(usize::MAX, 0).await;
        let client = Client::new(silent.addr).await.unwrap().with_retry(Duration::from_millis(10), 3);
        assert!(matches!(client.external_address().await, Err(NatPmpError::NoAnswer)));
        assert_eq!(silent.requests.lock().unwrap().len(), 3);
    }

    /// Only reads the routing table; sends nothing to the router.
    #[test]
    #[ignore = "depends on the machine's network"]
    fn real_default_gateway() {
        let gw = default_gateway().unwrap();
        println!("default gateway: {gw}");
        assert_eq!(gw.port(), NATPMP_PORT);
    }

    #[tokio::test]
    async fn test_forwarder_maps_and_renews() {
        let gw = fake_gateway(0, 0).await;
        let client = Client::new(gw.addr).await.unwrap();
        let external = Arc::new(Mutex::new(None));
        let ext = external.clone();
        // A 4 s lease is renewed after 3 s.
        let task = tokio::spawn(run_with_client(client, gw.addr, vec![6881], Duration::from_secs(4), move |ip| {
            *ext.lock().unwrap() = Some(ip);
        }));
        tokio::time::sleep(Duration::from_millis(500)).await;
        let first: Vec<_> = gw.requests.lock().unwrap().clone();
        assert_eq!(
            first,
            vec![
                vec![0, 0],
                encode_map_request(Protocol::Tcp, 6881, 6881, 4).to_vec(),
                encode_map_request(Protocol::Udp, 6881, 6881, 4).to_vec(),
            ]
        );
        assert_eq!(*external.lock().unwrap(), Some(Ipv4Addr::new(203, 0, 113, 7)));
        tokio::time::sleep(Duration::from_millis(3000)).await;
        assert_eq!(gw.requests.lock().unwrap().len(), 5, "both mappings renewed");
        task.abort();
    }
}
