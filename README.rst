Zero-conf p2p VPN
=================

*Disclaimer: This is a personal project. The views, code, and opinions expressed here are my own and do not represent those of my current or past employers.*

A lightweight peer-to-peer VPN daemon for establishing direct, authenticated
connections between trusted peers -- no central server, no account, no
dashboard.

You tell it which peers you trust, by their public key. It takes care of
finding them, connecting directly through NAT, and routing traffic to them --
automatically, and without relaying anyone else's traffic.

Why
---

* **No central server.** There's nothing to host, pay for, or lose trust in.
  Two peers that know each other's public key can connect directly.
* **IPv6-first, zero-config addressing.** Each peer's VPN address is derived
  from a cryptographic signature over its own key -- effectively random, so
  two peers can't collide by accident, yet deterministic and verifiable by
  anyone who knows the peer's public key. No address pool, no central
  allocator, no coordination between peers needed.
* **NAT traversal built in.** Transport is `QUIC <https://quicwg.org/>`_ over
  `iroh <https://iroh.computer>`_, which handles hole-punching through NATs
  and firewalls automatically -- no port forwarding and no public IP needed
  on either side. A relay is only ever used to help peers find each other,
  or as a last resort if a direct path can't be established.
* **Peers can't spoof each other.** The same signature that derives a peer's
  address also proves it: during the handshake, each side rejects any
  advertised address that isn't actually signed by that peer's key, so no
  peer can claim an address -- or an identity -- that isn't its own.
* **Direct connections only.** Peers never relay traffic for other peers.
  What you configure is exactly what can talk to what.
* **Efficient packet forwarding.** Packets move between the TUN device and
  QUIC through a preallocated buffer pool, with no per-packet allocation on
  the hot path.
* **Secure by default.** The packaged systemd unit runs as a dedicated,
  unprivileged user with only the one capability it actually needs
  (``CAP_NET_ADMIN``), under extensive sandboxing -- see below.
* Small, self-contained daemon with few runtime dependencies, written in
  Rust.

Quick start
-----------

1. Build the daemon:

   .. code:: sh

      $ cargo build --release

2. On each machine, generate a config and identity key:

   .. code:: sh

      $ ./target/release/zeroconf-p2p-vpn generate config.toml

   This writes ``config.toml`` and a fresh private key next to it, and prints
   the machine's public key.

3. Exchange public keys with the peer(s) you want to connect to (over any
   channel you already trust -- chat, a phone call, whatever), and add each
   one under ``[peers]`` in ``config.toml``:

   .. code:: toml

      [peers]
      alice = "ri5s1riaxztowkfasg645kdngnugembhsjwke5qfrktno9qjn8ty"

   That's it -- here's the complete config file at this point, in full,
   with the optional ``[dns]`` section added so that ``alice`` is also
   reachable by name (see `Peer names as DNS`_ below):

   .. code:: toml

      [host]
      private_key_path = "zeroconf-p2p-vpn_private.key"

      [peers]
      alice = "ri5s1riaxztowkfasg645kdngnugembhsjwke5qfrktno9qjn8ty"

      [dns]
      suffix = "p2p"

   No addresses, no subnets, no ports, nothing else to configure --
   everything else is derived automatically.

4. Run it (needs ``CAP_NET_ADMIN`` to create the TUN device and manage
   routes, so typically via ``sudo`` or the systemd unit below):

   .. code:: sh

      $ sudo ./target/release/zeroconf-p2p-vpn config.toml

Once both sides are running with each other's key configured, they connect
automatically and each peer's VPN address becomes reachable over the TUN
interface. Run ``zeroconf-p2p-vpn show config.toml`` at any time to print a
node's own public key and current configuration.

See ``example-config.toml`` for every available option (custom TUN interface
name, peer discovery mode, DNS for peer names -- see below).

Peer names as DNS
-----------------

Peers are otherwise reachable only by their VPN IP address. Giving the
``[dns]`` section a ``suffix`` turns the names already used in ``[peers]``
into real, resolvable DNS names, e.g. ``alice.p2p``, that always point at
wherever ``alice`` is currently reachable:

.. code:: toml

   [dns]
   suffix = "p2p"

This is implemented and tested on Linux (``systemd-resolved``, with
``resolvconf`` and a static ``/etc/resolv.conf`` edit as fallbacks). Windows
and macOS support is not yet wired up -- see ``DESIGN.rst`` for details.

Running as a systemd service
-----------------------------

See ``systemd/zeroconf-p2p-vpn.service`` for a hardened example unit,
including step-by-step install instructions in its header comment (static
service user, capability-only privileges, and the extra polkit rule needed if
you use the ``[dns]`` section).

Trying it out with Docker
--------------------------

``docker/`` has a two-node Docker Compose setup that brings up two containers
and connects them over the VPN -- see ``docker/README.rst``.

Design
------

For the architecture rationale, protocol details and implementation roadmap,
see ``DESIGN.rst``.
