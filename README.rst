Zero-conf p2p VPN
=================

Architectecture
---------------

* https://docs.rs/rtnetlink/latest/rtnetlink/ for manipulating routing tables

  Here is the comprehensive, highly detailed **Implementation Plan** for building your high-performance, zero-copy L3 VPN bridge in Rust. This plan reflects all architectural decisions approved during our discussion—from memory management to Linux kernel integration.

The plan is structured into logical, sequential phases.

---

### Single-Channel Buffer Pool

* **Technology:** `tokio::sync::mpsc`.
* **Key Points:**
* Create a **single shared channel** that acts as a "rental and return" queue for `BytesMut` buffers.
* Pre-allocate a fixed number of buffers (e.g., 128 or 256) at application startup and push them into this channel.
* Asynchronous routines (TUN reader, QUIC receiver) acquire a buffer from the channel, fill it with data, transfer its ownership (`move`) down the pipeline, and the final consumer pushes it back into the same channel after calling `.clear()`. This establishes a natural backpressure loop.

---

## PHASE 2: TUN Interface Initialization & Asynchronous I/O

In this phase, we set up the low-level reception and transmission of raw packets from the operating system.

### 1. Opening and Configuring `/dev/net/tun`

* **Technology:** Standard file operations, `nix` or `libc` for `ioctl`.
* **Key Points:**
* Open `/dev/net/tun` in Layer 3 mode (**`IFF_TUN`**).
* Strictly set the **`IFF_NO_PI`** (No Packet Information) flag. This ensures all packets read into the application begin directly with the IP header, simplifying parsing, guaranteeing compatibility, and preserving memory alignment.



### 2. Asynchronous Event Loop over TUN

* **Technology:** `tokio::io::AsyncReadExt` / `AsyncWriteExt` (with a future-proof path toward `io_uring`).
* **Key Points:**
* Leverage the guaranteed atomic nature of the Linux TUN interface: a single successful async read from the file descriptor yields **exactly one complete IP packet**. No custom framing or packet boundary detection is required.
* If a provided buffer is smaller than the incoming packet, the kernel drops it. Our 4096B limit provides an extensive safety margin over standard MTUs.



---

## PHASE 3: Network Logic, Filtering, and Kernel Integration (L3 Routing)

This phase transforms our application into an intelligent Point-to-Point router.

### 1. Addressing Scheme (Dual-Stack Point-to-Point)

* **IPv6:** Unique Local Addresses (ULA) range (**`fd00::/8`**), where each peer is assigned a unique **`/128` host address** (e.g., generated pseudonahodně or derived deterministically from a public key/certificate hash).
* **IPv4:** A private range (e.g., within `10.0.0.0/8`), where the local `tun0` is assigned an address with a **`/32`** netmask, and individual connected peers are given isolated **`/32`** addresses as well.

### 2. Dynamic Routing Table Management (The Source of Truth)

* **Technology:** **`rtnetlink`** (direct, high-speed binary communication with the Linux network stack).
* **Key Points:**
* The application maintains a local `HashMap<IpAddr, PeerHandle>` of currently connected users.
* **On-Connect (QUIC Session Established):** As soon as a peer authorizes and its IP is negotiated/assigned, the application immediately uses `rtnetlink` to inject host routes into the kernel: `ip -6 route add [PEER_IPv6]/128 dev tun0` and `ip route add [PEER_IPv4]/32 dev tun0`.
* **On-Disconnect (Connection Drop/Timeout):** The application detects the disconnection, removes the peer from the map, and immediately removes the respective routes from the kernel via `rtnetlink`. This prevents sending data blindly into a black hole (the kernel instantly returns *Network Unreachable* to local applications without waking up our TUN reader).



### 3. Fast-Path Filtering (The Gatekeeper)

* **Technology:** **`etherparse`**.
* **Key Points:**
* Even though routing decisions are delegated to the kernel, the application performs a zero-allocation validation of the first few bytes (the IP header) immediately after reading a packet from the TUN interface.
* It validates that the source IP matches the assigned peer and that the destination is legitimate. If validation fails, the packet is immediately dropped, and the buffer returns to the pool, preventing IP spoofing.



---

## PHASE 4: QUIC Transport Layer

This phase bridges local network traffic securely across the internet to the remote peer.

### 1. Data Channel (Unreliable Data Transfer)

* **Technology:** **`quinn`** (or `quiche`) – **QUIC Datagrams** (bounded by Path MTU).
* **Key Points:**
* IP packets approved by the filtering stage are asynchronously handed over to the QUIC stack as unreliable datagrams.
* If the underlying network drops a packet, retransmission is handled by the inner protocol (e.g., TCP running inside the tunnel). QUIC itself will not retransmit VPN data packets, avoiding the notorious "TCP-over-TCP" congestion collapse.



### 2. Control Plane (Reliable Signaling Stream)

* **Key Points:**
* A standard, reliable QUIC stream runs in parallel alongside the datagram transport.
* It handles the initial handshake, zero-conf IPv6/IPv4 address negotiation, and signaling messages (e.g., graceful disconnects or "add a subnet behind me" requests).



---

## PHASE 5: Architectural Overview of Async Loops (Data Flow)

After initialization, the entire application will be driven by three primary asynchronous tasks:

1. **TUN Reader Task:** Acquires an empty buffer from the pool $\rightarrow$ asynchronously reads a single packet from `tun0` $\rightarrow$ performs a lightning-fast validation using `etherparse` $\rightarrow$ looks up the destination IP in the peer map and transfers ownership (`move`) of the buffer to the corresponding QUIC writer task.
2. **QUIC Receiver Task:** Receives a QUIC datagram from the network $\rightarrow$ acquires an empty buffer from the pool and copies the data into it (or writes directly to it if the QUIC API supports it) $\rightarrow$ asynchronously writes the raw IP packet into `tun0` $\rightarrow$ clears and returns the buffer to the pool.
3. **Connection & Signaling Task:** Listens on Netlink sockets and the QUIC control stream $\rightarrow$ orchestrates connected clients and updates the Linux routing tables in real time.

This blueprint provides a cohesive, highly efficient system architecture that fully exploits Rust's ownership model and the native optimizations of the Linux kernel.



### Observability Implementation Strategy: Tracing & Telemetry

To ensure robust diagnostic capabilities, the system will utilize the Rust `tracing` ecosystem to capture structured event data. This telemetry will be serialized using the **OpenTelemetry Protocol (OTLP)** via the `prost` library to ensure performance and standardization.

#### Key Architectural Components

* **Telemetry Foundation:** The `tracing` crate will be used for instrumentation, providing the source for spans and events.
* **Serialization:** We will use `prost` to generate high-performance Protobuf code based on the official OTLP definitions. This ensures our binary format is both lean and natively compatible with modern observability backends (e.g., Jaeger, Honeycomb).
* **Transport Layer:** Tracing data will be transmitted over **QUIC streams**. This choice avoids head-of-line blocking and allows for efficient, multiplexed delivery of telemetry packets.

#### Handling Stream Dynamics

Regarding the "late-joiner" scenario where a consumer connects mid-stream and misses the beginning of active spans, the following approach will be taken:

1. **State Representation:** Since telemetry streams are inherently ephemeral, consumers connecting post-initiation will receive incomplete data for active spans (i.e., events lacking a recorded "start" event).
2. **Backend Resiliency:** We will leverage OTLP-compliant ingestion engines that are designed to handle incomplete span telemetry. These engines mitigate the impact of missing parent metadata by treating late-arriving events as continuous segments rather than orphaned entries.
3. **Future Mitigation:** If full state synchronization is required for specific operational requirements, we will implement a lightweight, on-demand state-sync protocol to broadcast the current "active span tree" upon a new subscriber's connection.

This design prioritizes performance and standard adherence while remaining flexible enough to accommodate future analytical requirements.
