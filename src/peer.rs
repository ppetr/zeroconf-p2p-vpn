use anyhow::{anyhow, Context, Error, Result};
use ipnet::IpNet;
use iroh::endpoint::Connection;
use iroh::{PublicKey, Signature};
use std::net::IpAddr;

use crate::addr;
use crate::proto;
use crate::route;

pub struct AllowedNetworks {
    networks: Vec<IpNet>,
}

pub struct Peer {
    key: PublicKey,
    conn: Connection,
    routes: Vec<route::ScopedRoute>,
}

/// Returns addresses that match
pub fn validate_addresses(
    allowed_nets: &[IpNet],
    advertise: &proto::v1::Advertise,
    key: &PublicKey,
) -> Result<Vec<IpNet>> {
    let mut valid = Vec::<IpNet>::with_capacity(advertise.own_addresses.len());
    let mut errors = Vec::<Error>::with_capacity(advertise.own_addresses.len());
    for host in &advertise.own_addresses {
        match validate_address(allowed_nets, host, key) {
            Ok(Some(net)) => valid.push(net),
            Ok(None) => (),
            Err(e) => {
                let e = e.context(format!("when parsing network '{}'", host.peer_network));
                tracing::info!("{}; host {}", e, key);
                errors.push(e);
            }
        }
    }
    if valid.is_empty() {
        Err(anyhow!("No valid addresses: {:?}", errors))
    } else {
        Ok(valid)
    }
}

pub fn validate_address(
    allowed_nets: &[IpNet],
    host: &proto::v1::HostAddress,
    key: &PublicKey,
) -> Result<Option<IpNet>> {
    let net: IpNet = host.peer_network.parse()?;
    let signature = Signature::try_from(host.peer_network_signature.as_slice())
        .context("Invalid cryptographic signature")?;
    addr::verify_signed_ipnet(host.peer_network.parse()?, key, &signature)?;
    let is_allowed = allowed_nets
        .into_iter()
        .any(|allowed| allowed.contains(&net));
    Ok(if is_allowed { Some(net) } else { None })
}
