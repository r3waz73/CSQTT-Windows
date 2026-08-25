// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use anyhow::{Context, Result, bail};
use primp::dns::{Addrs, Name, Resolve, Resolving};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
};

pub struct DnsResolver;

impl DnsResolver {
    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(vec![address]);
        }
        let mut addresses = Vec::new();
        for address in tokio::net::lookup_host((host, 0))
            .await
            .with_context(|| format!("DNS lookup {host}"))?
        {
            let address = address.ip();
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        if addresses.is_empty() {
            bail!("пустой DNS-ответ для {host}");
        }
        Ok(addresses)
    }
}

impl Resolve for DnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let resolver = global();
        Box::pin(async move {
            let addresses = resolver
                .lookup(&host)
                .await
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })?;
            Ok(Box::new(
                addresses
                    .into_iter()
                    .map(|address| SocketAddr::new(address, 0)),
            ) as Addrs)
        })
    }
}

pub fn global() -> Arc<DnsResolver> {
    static RESOLVER: OnceLock<Arc<DnsResolver>> = OnceLock::new();
    RESOLVER.get_or_init(|| Arc::new(DnsResolver)).clone()
}

pub async fn resolve_socket(address: &str) -> Result<SocketAddr> {
    if let Ok(address) = address.parse::<SocketAddr>() {
        return Ok(address);
    }
    let parsed = url::Url::parse(&format!("udp://{address}"))
        .with_context(|| format!("разбор адреса {address:?}"))?;
    let host = parsed.host_str().context("адрес не содержит имя хоста")?;
    let port = parsed.port().context("адрес не содержит порт")?;
    let ip = global()
        .lookup(host)
        .await?
        .into_iter()
        .next()
        .context("пустой DNS-ответ")?;
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn literal_socket_does_not_require_dns() {
        assert_eq!(
            resolve_socket("127.0.0.1:46000").await.unwrap(),
            "127.0.0.1:46000".parse().unwrap()
        );
        assert_eq!(
            resolve_socket("[::1]:46000").await.unwrap(),
            "[::1]:46000".parse().unwrap()
        );
    }
}
