// Modified by qbt-rs (https://github.com/linyisin/qbt-rs), 2026-11-18:
//   - ConnectionOptions::encryption / StreamConnector::encryption() (MSE/PE policy).
//   - 2026-11-22: HTTP proxies (http://, CONNECT tunnels) besides SOCKS5 for peer connections, and
//     ConnectionOptions::proxy_trackers_only (qBittorrent's "Use proxy for peer connections" off).
// Licensed under Apache-2.0 like the rest of rqbit; this notice satisfies section 4(b).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, bail};
use librqbit_dualstack_sockets::ConnectOpts;
use librqbit_utp::{BindDevice, UtpSocketUdp};
use serde::Serialize;
use tracing::debug;

use crate::{
    Error, PeerConnectionOptions, Result,
    type_aliases::{BoxAsyncReadVectored, BoxAsyncWrite},
    vectored_traits::AsyncReadVectoredIntoCompat,
};

#[derive(Debug, Clone, Copy, Serialize)]
pub enum ConnectionKind {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "utp")]
    Utp,
    #[serde(rename = "socks")]
    Socks,
}

impl std::fmt::Display for ConnectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionKind::Tcp => f.write_str("tcp"),
            ConnectionKind::Utp => f.write_str("uTP"),
            ConnectionKind::Socks => f.write_str("socks"),
        }
    }
}

pub struct ConnectionOptions {
    // socks5://[username:password@]host:port
    // If set, all outgoing connections will go through the proxy over TCP.
    // qbt-rs: http://[username:password@]host:port is accepted too (HTTP CONNECT).
    pub proxy_url: Option<String>,
    /// qbt-rs: use the proxy for tracker requests only, not for peer connections.
    pub proxy_trackers_only: bool,
    // TCP outgoing connections are enabled by default
    pub enable_tcp: bool,
    pub peer_opts: Option<PeerConnectionOptions>,
    /// qbt-rs: protocol encryption (MSE/PE) for outgoing and incoming connections.
    pub encryption: crate::mse::EncryptionPolicy,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            enable_tcp: true,
            proxy_url: None,
            proxy_trackers_only: false,
            peer_opts: None,
            encryption: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyKind {
    Socks5,
    /// qbt-rs: an HTTP proxy, tunnelling with CONNECT.
    Http,
}

#[derive(Debug, Clone)]
pub(crate) struct SocksProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username_password: Option<(String, String)>,
}

/// qbt-rs: a proxied stream of either kind.
trait ProxyStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ProxyStream for T {}

#[cfg(test)]
pub(crate) async fn http_connect_for_tests(proxy: &SocksProxyConfig, addr: SocketAddr) -> anyhow::Result<tokio::net::TcpStream> {
    http_connect(proxy, addr).await
}

/// qbt-rs: opens a tunnel to `addr` through an HTTP proxy (RFC 9110 CONNECT).
async fn http_connect(
    proxy: &SocksProxyConfig,
    addr: SocketAddr,
) -> anyhow::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .context("error connecting to the HTTP proxy")?;
    let mut request = format!("CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n");
    if let Some((user, pass)) = proxy.username_password.as_ref() {
        use base64::Engine;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    // Read the response head byte by byte, so nothing after it (peer data) is consumed.
    let mut head = Vec::with_capacity(256);
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 {
            bail!("the HTTP proxy's response is too long");
        }
        let mut byte = [0u8; 1];
        if stream.read(&mut byte).await? == 0 {
            bail!("the HTTP proxy closed the connection");
        }
        head.push(byte[0]);
    }
    let status_line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let status = std::str::from_utf8(status_line).unwrap_or_default().trim();
    let code = status.split_whitespace().nth(1).unwrap_or_default();
    if code != "200" {
        bail!("the HTTP proxy refused the tunnel: {status}");
    }
    Ok(stream)
}

#[derive(Default, Debug, Clone)]
pub(crate) struct StreamConnectorArgs {
    pub enable_tcp: bool,
    pub socks_proxy_config: Option<SocksProxyConfig>,
    pub utp_socket: Option<Arc<UtpSocketUdp>>,
    pub bind_device: Option<BindDevice>,
    pub ipv4_only: bool,
    pub encryption: crate::mse::EncryptionPolicy,
}

impl SocksProxyConfig {
    /// socks5h:// resolves hostnames via the proxy; socks5:// resolves them locally.
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        let url = ::url::Url::parse(url).context("invalid proxy URL")?;
        let kind = match url.scheme() {
            "socks5" | "socks5h" => ProxyKind::Socks5,
            "http" => ProxyKind::Http,
            other => anyhow::bail!("unsupported proxy URL scheme \"{other}\""),
        };
        let host = url.host_str().context("missing host")?;
        let port = url.port().context("missing port")?;
        let up = url
            .password()
            .map(|p| (url.username().to_owned(), p.to_owned()));
        Ok(Self {
            kind,
            host: host.to_owned(),
            port,
            username_password: up,
        })
    }

    async fn connect(
        &self,
        addr: SocketAddr,
    ) -> Result<(
        impl tokio::io::AsyncRead + Unpin + 'static,
        impl tokio::io::AsyncWrite + Unpin + 'static,
    )> {
        let proxy_addr = (self.host.as_str(), self.port);

        if self.kind == ProxyKind::Http {
            let stream: Box<dyn ProxyStream> = Box::new(http_connect(self, addr).await.map_err(Error::Anyhow)?);
            return Ok(tokio::io::split(stream));
        }
        let stream = if let Some((username, password)) = self.username_password.as_ref() {
            tokio_socks::tcp::Socks5Stream::connect_with_password(
                proxy_addr,
                addr,
                username.as_str(),
                password.as_str(),
            )
            .await?
        } else {
            tokio_socks::tcp::Socks5Stream::connect(proxy_addr, addr).await?
        };
        let stream: Box<dyn ProxyStream> = Box::new(stream);
        Ok(tokio::io::split(stream))
    }
}

gen_stats!(SingleStatAtomic SingleStatSnapshot, [
    attempts u64,
    successes u64,
    errors u64
], []);
gen_stats!(PerFamilyAtomic PerFamilySnapshot, [], [
    v4 SingleStatAtomic SingleStatSnapshot,
    v6 SingleStatAtomic SingleStatSnapshot
]);
gen_stats!(ConnectStatsAtomic ConnectStatsSnapshot, [], [
    socks PerFamilyAtomic PerFamilySnapshot,
    tcp PerFamilyAtomic PerFamilySnapshot,
    utp PerFamilyAtomic PerFamilySnapshot
]);

#[derive(Debug)]
pub(crate) struct StreamConnector {
    proxy_config: Option<SocksProxyConfig>,
    enable_tcp: bool,
    bind_device: Option<BindDevice>,
    utp_socket: Option<Arc<librqbit_utp::UtpSocketUdp>>,
    stats: ConnectStatsAtomic,
    ipv4_only: bool,
    encryption: crate::mse::EncryptionPolicy,
}

impl StreamConnector {
    pub async fn new(config: StreamConnectorArgs) -> anyhow::Result<Self> {
        #[allow(clippy::single_match)]
        match (
            config.socks_proxy_config.is_some(),
            config.enable_tcp,
            config.utp_socket.is_some(),
        ) {
            (false, false, false) => {
                bail!("no way to connect to peers, enable TCP, uTP or socks proxy")
            }
            _ => {
                // TODO: maybe validate other combinations. For now there's no way to disable TCP
            }
        }

        Ok(Self {
            proxy_config: config.socks_proxy_config,
            enable_tcp: config.enable_tcp,
            utp_socket: config.utp_socket,
            bind_device: config.bind_device,
            stats: Default::default(),
            ipv4_only: config.ipv4_only,
            encryption: config.encryption,
        })
    }

    /// qbt-rs: the protocol encryption policy (applies to outgoing and incoming connections).
    pub fn encryption(&self) -> crate::mse::EncryptionPolicy {
        self.encryption
    }

    fn get_stat(&self, kind: ConnectionKind, is_v6: bool) -> &SingleStatAtomic {
        let stat = match kind {
            ConnectionKind::Tcp => &self.stats.tcp,
            ConnectionKind::Utp => &self.stats.utp,
            ConnectionKind::Socks => &self.stats.socks,
        };
        if is_v6 { &stat.v6 } else { &stat.v4 }
    }

    async fn with_stat<R, E>(
        &self,
        kind: ConnectionKind,
        is_v6: bool,
        fut: impl Future<Output = std::result::Result<R, E>>,
    ) -> std::result::Result<R, E> {
        let stat = self.get_stat(kind, is_v6);
        stat.attempts(1);
        fut.await
            .inspect(|_| stat.successes(1))
            .inspect_err(|_| stat.errors(1))
    }

    async fn tcp_connect(
        &self,
        addr: SocketAddr,
    ) -> librqbit_dualstack_sockets::Result<tokio::net::TcpStream> {
        self.with_stat(
            ConnectionKind::Tcp,
            addr.is_ipv6(),
            librqbit_dualstack_sockets::tcp_connect(
                addr,
                ConnectOpts {
                    // Setting source port doesn't work with cloudflare warp on linux
                    // source_port: self.tcp_source_port,
                    source_port: None,
                    bind_device: self.bind_device.as_ref(),
                },
            ),
        )
        .await
    }

    pub fn stats(&self) -> &ConnectStatsAtomic {
        &self.stats
    }

    pub async fn connect(
        &self,
        addr: SocketAddr,
    ) -> Result<(ConnectionKind, BoxAsyncReadVectored, BoxAsyncWrite)> {
        if addr.port() == 0 {
            return Err(Error::Anyhow(anyhow::anyhow!(
                "invalid peer address (port 0): {}",
                addr
            )));
        }

        if self.ipv4_only && addr.is_ipv6() {
            return Err(Error::Anyhow(anyhow::anyhow!(
                "ipv6 disabled, skipping connection to {}",
                addr
            )));
        }

        if let Some(proxy) = self.proxy_config.as_ref() {
            let (r, w) = self
                .with_stat(ConnectionKind::Socks, addr.is_ipv6(), proxy.connect(addr))
                .await?;
            debug!(?addr, kind = ?proxy.kind, "connected through the proxy");
            return Ok((
                ConnectionKind::Socks,
                Box::new(r.into_vectored_compat()),
                Box::new(w),
            ));
        }

        // Try to connect over TCP first. If in 1 second we haven't connected, try uTP also (if configured).
        // Whoever connects first wins.
        let tcp_connect = async {
            if !self.enable_tcp {
                return Ok(None);
            }
            let conn = self.tcp_connect(addr).await?;
            debug!(?addr, "connected over TCP");
            Ok::<_, librqbit_dualstack_sockets::Error>(Some(conn))
        };

        let tcp_failed_notify = tokio::sync::Notify::new();

        let utp_connect = async {
            let sock = match self.utp_socket.as_ref() {
                Some(sock) => sock,
                None => return Ok(None),
            };

            // Give TCP priority as it's more mature and simpler.
            if self.enable_tcp {
                // wait until either 1 second has passed or TCP failed.
                tokio::select! {
                    _ = tcp_failed_notify.notified() => {},
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }

            let conn = self
                .with_stat(ConnectionKind::Utp, addr.is_ipv6(), sock.connect(addr))
                .await?;

            debug!(?addr, "connected over uTP");
            Ok(Some(conn))
        };

        tokio::pin!(tcp_connect);
        tokio::pin!(utp_connect);

        let mut tcp_err: Option<Option<librqbit_dualstack_sockets::Error>> = None;
        let mut utp_err: Option<Option<librqbit_utp::Error>> = None;

        // wait until all fail, or one succeeds.
        loop {
            if let (Some(tcp), Some(utp)) = (tcp_err.as_mut(), utp_err.as_mut()) {
                match (tcp.take(), utp.take()) {
                    (Some(tcp), Some(utp)) => return Err(Error::Connect { tcp, utp }),
                    (Some(tcp), None) => return Err(Error::TcpConnect(tcp)),
                    (None, Some(utp)) => return Err(Error::UtpConnect(utp)),
                    (None, None) => return Err(Error::ConnectDisabled),
                }
            }
            tokio::select! {
                tcp_res = &mut tcp_connect, if tcp_err.is_none() => {
                    match tcp_res {
                        Ok(Some(stream)) => {
                            let (r, w) = stream.into_split();
                            return Ok((ConnectionKind::Tcp, Box::new(r), Box::new(w)));
                        },
                        Ok(None) => {
                            tcp_err = Some(None);
                            tcp_failed_notify.notify_waiters();
                        }
                        Err(e) => {
                            tcp_err = Some(Some(e));
                            tcp_failed_notify.notify_waiters();
                        }
                    }
                },
                utp_res = &mut utp_connect, if utp_err.is_none() => {
                    match utp_res {
                        Ok(Some(stream)) => {
                            let (r, w) = stream.split();
                            return Ok((ConnectionKind::Utp, Box::new(r), Box::new(w)));
                        },
                        Ok(None) => {
                            utp_err = Some(None);
                        }
                        Err(e) => {
                            utp_err = Some(Some(e));
                        }
                    }
                },
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socks5() {
        let c = SocksProxyConfig::parse("socks5://myhost:1234").unwrap();
        assert_eq!(c.host, "myhost");
        assert_eq!(c.port, 1234);
        assert_eq!(c.username_password, None);
    }

    #[test]
    fn test_parse_socks5h() {
        let c = SocksProxyConfig::parse("socks5h://myhost:1234").unwrap();
        assert_eq!(c.host, "myhost");
        assert_eq!(c.port, 1234);
    }

    #[test]
    fn test_parse_with_password() {
        let c = SocksProxyConfig::parse("socks5h://user:pass@myhost:1234").unwrap();
        assert_eq!(c.host, "myhost");
        assert_eq!(c.port, 1234);
        assert_eq!(
            c.username_password,
            Some(("user".to_owned(), "pass".to_owned()))
        );
    }

    // qbt-rs: http:// is an HTTP CONNECT proxy now.
    #[test]
    fn test_parse_http() {
        let c = SocksProxyConfig::parse("http://u:p@myhost:1234").unwrap();
        assert_eq!(c.kind, ProxyKind::Http);
        assert_eq!((c.host.as_str(), c.port), ("myhost", 1234));
        assert_eq!(c.username_password, Some(("u".into(), "p".into())));
    }

    #[test]
    fn test_parse_rejects_other_schemes() {
        for url in [
            "https://myhost:1234",
            "socks4://myhost:1234",
            "socks4a://myhost:1234",
        ] {
            assert!(SocksProxyConfig::parse(url).is_err(), "should reject {url}");
        }
    }

    #[test]
    fn test_parse_rejects_garbage() {
        assert!(SocksProxyConfig::parse("not a url").is_err());
        assert!(SocksProxyConfig::parse("socks5://").is_err());
    }
}
