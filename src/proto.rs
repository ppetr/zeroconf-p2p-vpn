pub mod p2p_vpn { pub mod control { pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/p2p_vpn.control.v1.rs"));
}}}

use p2p_vpn::control::v1;
