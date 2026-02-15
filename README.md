# M13 

**Classification:** Aerospace / High-Frequency Transport (HFT) Grade  
**Target Hardware:** AMD/Xilinx Kria K26 SOM + Zynq UltraScale+ FPGA + Custom PCB  
**Testbench Architecture:** x86_64 (AVX2/AES-NI) for CI/CD and fixed ground-station Hubs  
**Operating System:** AMD Embedded Development Framework (EDF) Yocto Project (Scarthgap 5.0 LTS) / **Linux Kernel 6.12 LTS+**  
> **ARCHITECTURAL MANDATE:** Legacy PetaLinux distributions are explicitly End-of-Life (EOL) and physically incompatible with the M13 datapath. Kernel 6.12+ is a hard architectural requirement to enable `io_uring` Provided Buffer Rings (PBR), `IORING_RECV_MULTISHOT`, and advanced `XDP_REDIRECT` primitives.



## I. System Topology

M13 is a hardware-accelerated control and transport architecture engineered specifically for Beyond Visual Line of Sight (BVLOS) drone operations. It establishes a contiguous, end-to-end datapath between WAN-deprived tactical drone swarms and remote command centers by tightly coupling a localized WiFi 7 fronthaul with a bonded, multipath SATCOM backhaul. 

M13 executes entirely via kernel-bypass (`AF_XDP` and `io_uring`) on isolated CPU cores to strip all Virtual File System (VFS) overhead and provide a deterministic, line-rate transport pipeline. By enforcing zero-trust physical isolation and Post-Quantum Cryptographic (PQC) payload encapsulation, the system guarantees bounded-latency command execution and isochronous telemetry survival in heavily contested RF environments.

* **Hub (LALE Drone):** This module aggregates heterogeneous, asymmetric satellite uplinks (e.g., Starlink, Amazon Kuiper, Eutelsat) into a bonded, multipath-scheduled backhaul. It functions as a “flying telco” that broadcasts a WiFi 7 Access Point (AP) for the localized daughter drones. The Hub executes `AF_XDP` zero-copy packet processing, BBRv3 congestion pacing, and eBPF token buckets at hardware line-rate.
* **Nodes (WAN-deprived Daughter Drone Swarm):** This module comprises of tactical drone swarm lacking inherent Wide Area Network (WAN) hardware interfaces. The Nodes associate with the Hub's WiFi 7 AP, achieving end-to-end connectivity to the User exclusively via the M13 L3 encrypted tunnel over the local WLAN. To bypass VFS overhead in the absence of `AF_XDP` support over `mac80211`, the Node utilizes an `IORING_SETUP_SQPOLL`-configured `io_uring` Multishot ingest, mapping the buffer to a HugePage Arena.
* **User (Command Center):** This constitutes the remote infrastructure connected via a standard Internet Service Provider (ISP). M13 operates strictly at the transport layer, acting as a transparent, opaque IP tunnel that remains entirely agnostic to the L7 application protocols (MAVLink/Video) executing above it.

### Data Flow Physics

**Commands (Downstream - Low Latency, Strict Priority):**
```text
User PC ──Fiber──→ ISP ──Fiber──→ Satellite Constellation ──→ Hub (AF_XDP) ──WiFi 7──→ Node (io_uring)

```

**Telemetry/Video (Upstream - High Throughput, Isochronous):**

```text
Node (io_uring) ──WiFi 7──→ Hub (O(1) Re-Order Buffer) ──Multi-Path LEO/MEO──→ Satellite Constellation ──Fiber──→ ISP ──→ User PC

```

---

## II. Source Tree Architecture

```text
m13/
├── Cargo.toml                      ← workspace: [hub, node], release: LTO, panic=abort, codegen-units=1
├── README.md
├── TODO.md                         ← Roadmap & technical debt ledger
│
├── hub/                            ← THE HUB (AF_XDP / Satellite Aggregator)
│   ├── Cargo.toml                  ← libc, ring, libbpf-sys, bytemuck, ml-kem, ml-dsa, sha2, hkdf, rand
│   ├── build.rs                    ← eBPF object compilation & kernel bindgen
│   ├── m13-hub.bb                  ← Yocto BitBake recipe
│   ├── m13-hub.p4                  ← P4 behavioral model
│   ├── tests/
│   │   └── pipeline.rs             ← VPP graph integration tests
│   └── src/
│       ├── lib.rs                  ← Public re-exports for tests
│       ├── main.rs                 ← Orchestrator: main → run_executive → worker_entry → VPP loop
│       ├── engine/
│       │   ├── mod.rs              ← pub mod protocol, runtime, spsc
│       │   ├── protocol.rs         ← Wire format, PeerTable, Scheduler, JitterBuffer, RxBitmap
│       │   ├── runtime.rs          ← TscCal, HexdumpState, Telemetry, FixedSlab, core pinning
│       │   └── spsc.rs             ← Wait-free SPSC lock-free ring (128-byte CachePadded)
│       ├── network/
│       │   ├── mod.rs              ← PacketVector, PacketDesc, GraphCtx, CycleStats, Disposition, scatter
│       │   ├── xdp.rs              ← AF_XDP Engine (1GB HugeTLB UMEM, ZeroCopyTx, XDP_ZEROCOPY)
│       │   ├── bpf.rs              ← BPF Steersman (direct attach, no Option fallback)
│       │   └── datapath.rs         ← VPP graph nodes, tun_read_batch (demand-driven SPSC), tun_write_vector
│       └── cryptography/
│           ├── mod.rs
│           ├── aead.rs             ← AES-256-GCM: seal_frame, open_frame, encrypt/decrypt_batch_ptrs
│           └── handshake.rs        ← PQC: ML-KEM-1024 + ML-DSA-87, process_client_hello_hub
│
└── node/                           ← THE NODE (io_uring / Edge Endpoint)
    ├── Cargo.toml                  ← libc, ring, io-uring 0.7, bytemuck, ml-kem, ml-dsa, sha2, hkdf, rand
    ├── build.rs                    ← Kernel bindgen
    ├── m13-node.bb                 ← Yocto BitBake recipe
    ├── m13-node.p4                 ← P4 behavioral model
    └── src/
        ├── main.rs                 ← Orchestrator: main → run_uring_worker (CQE three-pass loop)
        ├── engine/
        │   ├── mod.rs              ← pub mod protocol, runtime
        │   ├── protocol.rs         ← Wire format, Assembler, fragment TX, build_m13_frame
        │   └── runtime.rs          ← TscCal, NodeState FSM, HexdumpState
        ├── network/
        │   ├── mod.rs              ← pub mod datapath, uring_reactor
        │   ├── datapath.rs         ← TUN creation, route setup/teardown, nuke_cleanup
        │   └── uring_reactor.rs    ← io_uring SQPOLL + PBR zero-syscall reactor
        └── cryptography/
            ├── mod.rs
            ├── aead.rs             ← AES-256-GCM: seal_frame, open_frame, decrypt_batch_ptrs (4-wide AES-NI)
            └── handshake.rs        ← PQC: ML-KEM-1024 + ML-DSA-87, initiate_handshake (client side)
```

---

## III. Phase 0: Silicon Provisioning & Micro-Architecture Isolation

### Target Flight Hardware: AMD/Xilinx K26 SOM (Hub & Node)

**Silicon Geometry:** The Zynq UltraScale+ MPSoC possesses a **Quad-Core ARM Cortex-A53**.

*   **Core 0:** Reserved for Linux Housekeeping (SMMU, VFS locks, SSH, unpinned hardIRQs).
*   **Cores 1, 2, 3:** Physically isolated for M13's Net I/O, Datapath, and Crypto threads.
*   **Memory:** 4GB total DDR4. We lock 512MB (`hugepages=256`) for the zero-copy Arenas.

**Implementation (Yocto EDF / U-Boot):**
Do not attempt to use `update-grub`. Append the kernel parameters via your Yocto `machine.conf`, Device Tree (`system-user.dtsi`), or dynamically at runtime via `extlinux.conf`.

```bash
# 1. Modify the U-Boot extlinux configuration on the K26 SOM
sudo sed -i '/^[[:space:]]*append/ s/$/ isolcpus=1,2,3 rcu_nocbs=1,2,3 nohz_full=1,2,3 irqaffinity=0 hugepagesz=2M hugepages=256/' /boot/extlinux/extlinux.conf

# 2. Sync filesystem and reboot to apply silicon isolation
sync && sudo reboot

```

> **Verification Post-Reboot:**
> 1. Verify CPU Isolation: `cat /sys/devices/system/cpu/isolated` → Must output exactly `1-3`.
> 2. Verify HugePage allocation: `cat /proc/sys/vm/nr_hugepages` → Must output `256`.
> *If either check fails, the pipeline will fall back to the CFS scheduler and the mission MUST be aborted.*
> 

### Build Dependencies (Run on K26 or Cross-Compile Host)

```bash
# Install Rust HFT Toolchain & Kernel 6.12+ Headers
sudo apt update && sudo apt install -y curl build-essential clang llvm libbpf-dev pkg-config libelf-dev make linux-headers-$(uname -r)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable && rustup update

```

---

## IV. Phase 1: Build & Execution Chains

### 1. Hub Build

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release --manifest-path hub/Cargo.toml
```

**What happens:**

1.  **`hub/build.rs`** executes first:
    -   Compiles the eBPF XDP object from inline C via `clang -target bpf`
    -   Runs `bindgen` against kernel headers to generate `ethtool_ringparam`, `ifreq` FFI bindings
    -   Emits `OUT_DIR/m13_xdp.o` (the XDP redirect program) and `OUT_DIR/bindings.rs`

2.  **`rustc`** compiles the workspace with release profile:
    -   `panic = "abort"` — no unwind tables, smaller binary
    -   `lto = true` — whole-program link-time optimization across all crates
    -   `codegen-units = 1` — maximum optimization (no parallel codegen splitting)
    -   `-C target-cpu=native` — AVX2/AES-NI intrinsics on x86_64, NEON/CE on aarch64

3.  **Output:** `target/release/m13-hub` (statically linked, symbols stripped)

### 2. Hub Execution

```bash
sudo RUST_LOG=debug ./target/release/m13-hub enp1s0f0 --tunnel --single-queue 0
```

**Exact execution sequence** (`hub/src/main.rs`):

```text
main() [L42]
├── Signal handlers: SIGTERM/SIGINT → AtomicBool SHUTDOWN [L46-48]
├── Panic hook: nuke_cleanup_hub() on unwind [L52-57]
├── CLI parse: if_name="enp1s0f0", tunnel=true, single_queue=Some(0) [L63-101]
├── Set M13_LISTEN_PORT=443 (default) [L107-121]
└── run_executive(&if_name, single_queue, tunnel) [L122]

run_executive() [L126]
├── Pre-flight cleanup [L136-183]:
│   ├── Kill stale m13-hub processes via pgrep/SIGKILL [L139-151]
│   ├── Detach stale XDP: ip link set <if> xdp off [L154-155]
│   ├── [R-01] ethtool -L <if> combined 1 — collapse NIC to single queue [L157-174]
│   └── Auto-allocate hugepages: write (workers × UMEM_SIZE / 2MB) to procfs [L176-182]
├── TSC calibration (rdtsc loop) [L187]
├── lock_pmu() + fence_interrupts() + discover_isolated_cores() [L189-193]
├── Worker count = 1 (single-queue mode) [L197-200]
├── [R-01] BpfSteersman::load_and_attach(if_name) → direct return (panics on failure) [L205-206]
├── Create TUN interface m13tun0 + setup_nat() [L210-214]
│
├── [R-02A] SPSC Ring Creation [L216-225]:
│   ├── 4 rings × depth 2048:
│   │   ├── tx_tun: Producer<PacketDesc> → Consumer<PacketDesc>     (datapath → TUN HK)
│   │   ├── rx_tun: Producer<PacketDesc> → Consumer<PacketDesc>     (TUN HK → datapath)
│   │   ├── free_to_tun: Producer<u32> → Consumer<u32>             (datapath → TUN HK slab IDs)
│   │   └── free_to_dp: Producer<u32> → Consumer<u32>              (TUN HK → datapath slab IDs)
│   └── OnceLock<(usize, u32)> for UMEM base sharing [L230-231]
│
├── [R-02A] TUN Housekeeping Thread spawn [L234-252]:
│   ├── Pinned to last isolated core
│   ├── Receives: tx_tun_cons, rx_tun_prod, free_to_tun_cons, free_to_dp_prod, umem_info
│   └── tun_housekeeping_thread() [L759-933]:
│       ├── Block until OnceLock published by Worker 0 [L774-783]
│       ├── DPDK-style local cache: [u32; 4096] pending_return [L790]
│       └── Main loop:
│           ├── Phase 0: Drain pending_return → free_slab_tx [L808-815]
│           ├── Phase 1 (TX): Pop PacketDesc from rx_from_dp → write(tun_fd) → return slab [L820-852]
│           └── Phase 2 (RX): poll(POLLIN,1ms) → alloc from free_slab_rx → read(tun_fd) → 
│               build Eth+M13 header in UMEM → push PacketDesc to tx_to_dp [L858-919]
│
├── Worker 0 handle distribution via .take() [L260-276]:
│   └── Only worker 0 gets SPSC Producer/Consumer handles
│
└── worker_entry() [L938]:
    ├── pin_to_core(core_id) + verify_affinity() [L947-948]
    ├── Engine::new_zerocopy(if_name, queue_id, bpf_map_fd) → AF_XDP bind [L952]
    ├── [R-02A] umem_info.set((umem_base, FRAME_SIZE)) → unblock TUN HK [L956-959]
    ├── FixedSlab::new(8192), Scheduler, PeerTable, ReceiverState [L961-972]
    ├── Pre-stamp all 8192 slab frames with Eth+M13 headers [L1000-1015]
    │
    └── VPP Main Loop [L1016+]:
        ├── SHUTDOWN check [L1029]
        ├── engine.recycle_tx() + engine.refill_rx() [L1080-1081]
        │
        ├── TUN TX Graph (worker 0 only) [L1086-1116]:
        │   ├── Build GraphCtx with SPSC handles [L1087-1112]
        │   │   tx_tun_prod, rx_tun_cons, free_to_tun_prod, free_to_dp_cons
        │   └── execute_tx_graph(&mut ctx) → tun_read_batch():
        │       ├── Reclaim returned slabs: free_to_dp_cons.pop_batch() → slab.free() [datapath.rs:530-536]
        │       ├── Demand-driven provision: free_to_tun_prod.available() → bounded alloc [datapath.rs:538-562]
        │       └── Pop pre-built TUN frames: rx_tun_cons.pop_batch() → inject [datapath.rs:565-574]
        │
        ├── RX Graph [L1135-1245]:
        │   ├── engine.poll_rx() → PacketVector [L1143]
        │   ├── scatter() → per-packet classification [network/mod.rs]
        │   ├── VPP graph nodes: rx_parse, classify, aead_decrypt_vector, handshake
        │   ├── tun_write_vector() → SPSC push or VFS fallback [datapath.rs]
        │   └── Build GraphCtx with SPSC handles [L1178-1230]
        │
        └── Telemetry: 1/sec report [L1117-1132]:
            RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD:{}/{} HS:{}/{} Slab:{}/{} Peers:{}/{}
```

### 3. Node Build

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release --manifest-path node/Cargo.toml
```

**What happens:**

1.  **`node/build.rs`** executes first:
    -   Runs `bindgen` against kernel headers to generate `ethtool_ringparam`, `ifreq` FFI bindings
    -   Emits `OUT_DIR/bindings.rs`

2.  **`rustc`** compiles with identical release profile (LTO, panic=abort, codegen-units=1, target-cpu=native)

3.  **`io-uring = "0.7"`** crate provides safe Rust bindings for `io_uring` syscalls

4.  **Output:** `target/release/m13-node`

### 4. Node Execution

```bash
sudo RUST_LOG=debug ./target/release/m13-node --hub-ip 67.213.122.195:443 --tunnel
```

**Exact execution sequence** (`node/src/main.rs`):

```text
main() [L36]
├── Signal handlers: SIGTERM/SIGINT → AtomicBool SHUTDOWN [L41-43]
├── Panic hook: nuke_cleanup_node() [L47-51]
├── CLI parse: echo=false, hexdump=false, tunnel=true [L53-55]
├── create_tun("m13tun0") → TUN fd [L59-63]
├── Parse --hub-ip "67.213.122.195:443" [L66-73]
├── Store Hub IP in HUB_IP_GLOBAL Mutex (for panic hook route teardown) [L77-79]
└── run_uring_worker(&ip, echo, hexdump, tun_file) [L80]

run_uring_worker() [L700]
├── TSC calibration: calibrate_tsc() [L703]
├── System tuning: tune_system_buffers() [L704]
│   └── sysctl: net.core.rmem_max, wmem_max, netdev_max_backlog [L304-326]
├── UdpSocket::bind("0.0.0.0:0") → connect(hub_addr) [L707-710]
├── Socket tuning: SO_RCVBUFFORCE=8MB, SO_SNDBUFFORCE=8MB [L716-722]
│
├── UringReactor::new(raw_fd, cpu=0) [L728]:
│   ├── uring_reactor.rs [L72-145]:
│   │   ├── HugeTLB mmap: 2MB-aligned arena (PBR metadata + data frames) [L76-86]
│   │   ├── IoUring::builder().setup_sqpoll(2000ms).setup_single_issuer() [L87-96]
│   │   ├── SYS_io_uring_register IORING_REGISTER_PBUF_RING [L98-116]
│   │   └── Pre-register all BIDs in PBR [L118-128]
│   └── arm_multishot_recv() → single SQE for lifetime of socket [L147-165]
│
├── TUN fd extraction + arm TUN reads [L732-740]
├── Counter init: seq_tx, rx/tx/aead/tun counters [L742-748]
├── Build M13 header template (src_mac, hub_mac, magic, version) [L767-773]
├── Send initial registration frame [L760-762]
├── State machine init: NodeState::Registering [L764]
│
└── CQE Three-Pass Main Loop [L777+]:
    ├── SHUTDOWN check [L778]
    ├── Connection timeout: 30s pre-Established [L782-786]
    │
    ├── ═══ Pass 0: CQE Drain + Classify ═══ [L798-890]
    │   ├── reactor.ring.completion().sync() [L799]
    │   ├── Drain up to 128 CQEs into cqe_batch[] [L800-808]
    │   ├── For each CQE, classify by tag:
    │   │   ├── TAG_UDP_RECV_MULTISHOT → collect into recv_bids[]/recv_lens[] [L823-842]
    │   │   ├── TAG_TUN_READ → build M13 header in-place → seal_frame → stage_udp_send [L846-874]
    │   │   ├── TAG_TUN_WRITE → recycle BID to PBR [L876-879]
    │   │   └── TAG_UDP_SEND_TUN/ECHO → arm_tun_read(bid) to recycle BID [L881-886]
    │   └── recv_count = number of UDP recv CQEs in this batch
    │
    ├── ═══ Pass 1: Vectorized AEAD Batch Decrypt ═══ [L892-937]
    │   ├── If Established AND recv_count > 0:
    │   │   ├── Scan recv frames for crypto_flag == 0x01 → collect enc_ptrs[] [L903-918]
    │   │   ├── decrypt_batch_ptrs(enc_ptrs, enc_lens, enc_count, cipher) [L920-927]
    │   │   │   └── 4-at-a-time AES-NI prefetch saturates crypto pipeline
    │   │   │   └── Stamps PRE_DECRYPTED_MARKER (0x02) on success
    │   │   └── Rekey check: frame_count >= limit || time > limit [L930-934]
    │
    ├── ═══ Pass 2: Per-Frame RxAction Dispatch ═══ [L939-1026]
    │   ├── For each recv frame (PRE_DECRYPTED_MARKER skips scalar decrypt):
    │   │   ├── process_rx_frame() → RxAction [L954-955]
    │   │   ├── RxAction::NeedHandshakeInit → initiate_handshake() (PQC ClientHello) [L959-962]
    │   │   ├── RxAction::TunWrite → stage_tun_write(tun_fd, ptr, len, bid) [L964-973]
    │   │   ├── RxAction::Echo → build_echo_frame → seal_frame → sock.send [L975-985]
    │   │   ├── RxAction::HandshakeComplete → derive AEAD key → NodeState::Established [L987-1011]
    │   │   │   └── setup_tunnel_routes(&hub_ip) [L1007-1010]
    │   │   ├── RxAction::HandshakeFailed → NodeState::Disconnected [L1012-1015]
    │   │   └── RxAction::RekeyNeeded → NodeState::Registering [L1016-1018]
    │   └── Recycle BID to PBR (unless deferred by TunWrite) [L1022-1025]
    │
    ├── Re-arm multishot recv if terminated [L1028-1031]
    ├── Handshake timeout → re-register [L1033-1043]
    ├── Keepalive: 100ms, pre-Established only [L1045-1052]
    ├── Telemetry: 1/sec [L1054-1067]:
    │   RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} State:{}
    └── reactor.submit() + submit_and_wait(0) [L1069-1071]
```

---

## V. Connection Lifecycle: Registration → PQC Handshake → Established Tunnel

This section traces the **complete end-to-end datapath** from the moment a Node starts to the point where bidirectional AEAD-encrypted tunnel traffic flows. Every step is canonical, deterministic, and traceable to a specific source location.

### Wire Protocol Constants

| Constant | Value | Defined In |
|----------|-------|-----------|
| `M13_WIRE_MAGIC` | `0xD1` | `engine/protocol.rs` |
| `M13_WIRE_VERSION` | `0x01` | `engine/protocol.rs` |
| `ETH_P_M13` | `0x88B5` | `engine/protocol.rs` |
| `FLAG_CONTROL` | `0x80` | `engine/protocol.rs` |
| `FLAG_HANDSHAKE` | `0x10` | `engine/protocol.rs` |
| `FLAG_FRAGMENT` | `0x08` | `engine/protocol.rs` |
| `FLAG_TUNNEL` | `0x01` | `engine/protocol.rs` |
| `HS_CLIENT_HELLO` | `0x01` | `engine/protocol.rs` |
| `HS_SERVER_HELLO` | `0x02` | `engine/protocol.rs` |
| `HS_FINISHED` | `0x03` | `engine/protocol.rs` |
| `DIR_HUB_TO_NODE` | `0x00` | `engine/protocol.rs` |
| `DIR_NODE_TO_HUB` | `0x01` | `engine/protocol.rs` |

### Message Sizes

| Message | Composition | Total |
|---------|------------|-------|
| ClientHello (Msg 1) | type(1) + version(1) + nonce(32) + ML-KEM-1024 ek(1568) + ML-DSA-87 pk(2592) | **4,194 B** |
| ServerHello (Msg 2) | type(1) + ML-KEM-1024 ct(1568) + ML-DSA-87 pk(2592) + ML-DSA-87 sig(4627) | **8,788 B** |
| Finished (Msg 3) | type(1) + ML-DSA-87 sig(4627) | **4,628 B** |
| Fragment MTU | 1402 B payload (MTU 1500 − IP(20) − UDP(8) − M13 overhead(70)) | — |
| ClientHello fragments | ⌈4194 / 1402⌉ | **3 fragments** |
| ServerHello fragments | ⌈8788 / 1402⌉ | **7 fragments** |
| Finished fragments | ⌈4628 / 1402⌉ | **4 fragments** |

### Protocol Timing Constants

| Constant | Value | Defined In |
|----------|-------|----------|
| `HANDSHAKE_TIMEOUT_NS` | 5 s (`5_000_000_000`) | `engine/protocol.rs:42` |
| `REKEY_FRAME_LIMIT` | 2³² frames (`1u64 << 32`) | `engine/protocol.rs:44` |
| `REKEY_TIME_LIMIT_NS` | 3600 s (`3_600_000_000_000`) | `engine/protocol.rs:46` |
| Keepalive interval | 100 ms (`100_000_000` ns) | `main.rs` (inline) |
| Connection timeout | 30 s (`30_000_000_000` ns) | `main.rs` (inline, io_uring path) |

### AEAD Wire Geometry (M13 Header Byte Map)

AEAD operates on the 48-byte M13 header starting at `offset` (ETH_HDR_SIZE for L2, or 56 for UDP).

```text
offset +  0: signature[0] = M13_WIRE_MAGIC (0xD1)     ─┐
offset +  1: signature[1] = M13_WIRE_VERSION (0x01)    │ AAD (4 bytes)
offset +  2: signature[2] = crypto_ver                 │  0x00=cleartext, 0x01=encrypted
offset +  3: signature[3] = reserved (0x00)            ─┘
offset +  4: signature[4..20]  = AEAD tag (16 bytes)      ← GCM authentication tag
offset + 20: signature[20..32] = nonce (12 bytes)         ← seq_id(8) || direction(1) || zeros(3)
offset + 32: [encrypted region begins]                    ← seq_id, flags, payload_len, padding (16B)
offset + 48: [payload begins]                             ← IP packet or fragment data
```

**Nonce construction** (`seal_frame`, line 14-15 in `aead.rs`):
- `nonce[0..8]` = `seq_id` as LE u64 (full 64-bit sequence number)
- `nonce[8]` = `direction` byte (`0x00` = Hub→Node, `0x01` = Node→Hub)
- `nonce[9..12]` = `0x00` (zero-padded to 12 bytes)
- **Reflection guard**: `open_frame` rejects if `nonce[8] == our_dir`, preventing self-inflicted replay.

### Sequence Diagram

```text
    Node                                      WAN (UDP)                                  Hub
     │                                            │                                       │
     │  ┌─────────────────────────────────┐       │                                       │
     │  │ 0. build_m13_frame(FLAG_CONTROL)│       │                                       │
     │  │    → NodeState::Registering     │       │                                       │
     │  └─────────────────────────────────┘       │                                       │
     │ ═══ Registration Frame (62B) ══════════════╬════════════════════════════════════=═►│
     │                                            │  rx_parse_raw() → lookup_or_insert()  │
     │                                            │  → PeerSlot allocated, PeerAddr saved │
     │                                            │  classify: FLAG_CONTROL → Consumed    │
     │                                            │  (Hub does NOT echo — silent insert)  │
     │ ... keepalive probes (100ms) ...           │                                       │
     │ ═══ Keepalive (62B, FLAG_CONTROL) ═════════╬════════════════════════════════════=═►│
     │                                            │  (Consumed — refreshes NAT binding)   │
     │                                            │                                       │
     │  ┌─────────────────────────────────┐       │                                       │
     │  │ 1. On receipt of any valid M13  │       │                                       │
     │  │    frame while Registering:     │       │                                       │
     │  │    process_rx_frame() →         │       │                                       │
     │  │    RxAction::NeedHandshakeInit  │       │                                       │
     │  │    → initiate_handshake()       │       │                                       │
     │  │    → ML-KEM-1024 keygen         │       │                                       │
     │  │    → ML-DSA-87 keygen           │       │                                       │
     │  │    → NodeState::Handshaking     │       │                                       │
     │  └─────────────────────────────────┘       │                                       │
     │ ═══ ClientHello (4194B, 3 frags) ══════════╬═══════════════════════════════════=══►│
     │                                            │  rx_parse_raw() → classify (FRAGMENT) │
     │                                            │  → Assembler::feed() × 3              │
     │                                            │  → reassembly complete                │
     │                                            │  → process_handshake_message()        │
     │                                            │  ┌──────────────────────────────────┐ │
     │                                            │  │ 2. process_client_hello_hub()    │ │
     │                                            │  │    validate type/version/length  │ │
     │                                            │  │    ML-KEM-1024 encapsulate → ss  │ │
     │                                            │  │    ML-DSA-87 keygen              │ │
     │                                            │  │    SHA-512(CH || ct) → transcript│ │
     │                                            │  │    sign(transcript) → sig_hub    │ │
     │                                            │  │    → PeerLifecycle::Handshaking  │ │
     │                                            │  │    → HubHandshakeState stored    │ │
     │                                            │  └──────────────────────────────────┘ │
     │◄═══════════════════════════════════════════╬══ ServerHello (8788B, 7 frags) ═══════│
     │                                            │  build_fragmented_raw_udp()           │
     │  ┌─────────────────────────────────┐       │  → slab.alloc() × 7                   │
     │  │ Assembler::feed() × 7           │       │  → scheduler.enqueue_critical() × 7   │
     │  │ → reassembly complete           │       │                                       │ 
     │  │ 3. process_handshake_node()     │       │                                       │ 
     │  │    ML-KEM-1024 decapsulate → ss │       │                                       │
     │  │    SHA-512(CH || ct) → verify   │       │                                       │
     │  │    pk_hub.verify(transcript,sig)│       │                                       │
     │  │    HKDF-SHA-512(nonce,ss) → key │       │                                       │
     │  │    SHA-512(CH || SH) → sign     │       │                                       │
     │  │    → HandshakeComplete          │       │                                       │
     │  └─────────────────────────────────┘       │                                       │
     │ ═══ Finished (4628B, 4 frags) ═════════════╬══════════════════════════════════════►│
     │                                            │  Assembler::feed() × 4                │
     │                                            │  → reassembly complete                │
     │  ┌─────────────────────────────────┐       │  ┌──────────────────────────────────┐ │
     │  │ 4. Install AEAD cipher          │       │  │ 4. process_finished_hub()        │ │
     │  │    AES-256-GCM(session_key)     │       │  │    SHA-512(CH || SH) → transcript│ │
     │  │    NodeState::Established       │       │  │    pk_node.verify(transcript,sig)│ │
     │  │    Keepalives STOP              │       │  │    HKDF-SHA-512(nonce,ss) → key  │ │
     │  │    setup_tunnel_routes()        │       │  │    Install AES-256-GCM cipher    │ │
     │  └─────────────────────────────────┘       │  │    PeerLifecycle::Established    │ │
     │                                            │  └──────────────────────────────────┘ │
     │                                            │                                       │
     │ ═══ AEAD Tunnel Traffic ═══════════════════╬══════════════════════════════════════►│
     │◄═══════════════════════════════════════════╬═══════════════════════ AEAD Tunnel ═══│
     │                                            │                                       │
     │  ┌─ Failure Paths ─────────────────────────┼──────────────────────────────────────┐│
     │  │ • HS timeout (5s):  re-register + Assembler::new → Step 0                      ││
     │  │ • Conn timeout (30s, io_uring): process exit                                   ││
     │  │ • Rekey (2³² frames or 3600s): → Registering → Step 0 (session key rotated)    ││
     │  │ • HS failure: → Disconnected (wait for next valid frame → Registering)         ││
     │  └────────────────────────────────────────────────────────────────────────────────┘│
```

### Step-by-Step Code Trace

#### Step 0: Node Sends Registration Frame

The Node sends a single 62-byte cleartext M13 frame with `FLAG_CONTROL` to establish a return path with the Hub. This is the very first packet on the wire.

```text
Node — node/src/main.rs
├── build_m13_frame(&src_mac, &hub_mac, seq_tx, FLAG_CONTROL)  [protocol.rs:59]
│   ├── Builds: ETH(14) + M13(48) = 62 bytes
│   ├── EtherType: 0x88B5 (big-endian)
│   ├── M13: magic=0xD1, version=0x01, seq_id=LE, flags=FLAG_CONTROL
│   └── Direction: Not set (cleartext control frame)
├── sock.send(&reg)                                            [main.rs:394 / 762]
│   └── UDP connected socket → Hub IP:443
└── state = NodeState::Registering                             [main.rs:396 / 764]
```

#### Step 1: Hub Discovers Node (Peer Table Insert)

The Hub's AF_XDP engine receives the UDP-encapsulated registration frame. The VPP `rx_parse_raw()` node extracts the source IP:port, inserts a new peer slot, and classifies the frame. **The Hub does NOT echo or reply** — `FLAG_CONTROL` frames are silently consumed. The Node's keepalive probes (every 100ms) serve only to maintain the NAT binding until the ClientHello exchange begins.

```text
Hub — hub/src/network/datapath.rs
├── rx_parse_raw()                                             [datapath.rs:24]
│   ├── Detect encapsulation: EtherType 0x0800 (IPv4/UDP)      [datapath.rs:70]
│   ├── Extract src_ip from IP header [26..30]                  [datapath.rs:73]
│   ├── Extract src_port from UDP header [34..36]               [datapath.rs:74]
│   ├── Learn hub_ip from dst_ip [30..34] (first packet only)   [datapath.rs:81-84]
│   ├── Learn gateway_mac from src_mac [0..6] (first packet)    [datapath.rs:86-89]
│   ├── PeerAddr::new_udp(src_ip, src_port)                     [datapath.rs:94]
│   ├── peers.lookup_or_insert(peer_addr, peer_mac)             [datapath.rs:96]
│   │   └── First time: allocates PeerSlot, stores PeerAddr + MAC
│   ├── M13 offset = 56 (ETH(14) + IP(20) + UDP(8) + FakeETH(14))
│   ├── Validate magic=0xD1, version=0x01                       [datapath.rs:116-118]
│   └── Route: crypto_ver=0x00 → cleartext_out PacketVector     [datapath.rs:132-140]
│
└── classify_route()                                            [datapath.rs:385+]
    └── FLAG_CONTROL → NextNode::Consumed                       [datapath.rs:401]
        └── Silent consumption: Hub does NOT transmit any response
```

#### Step 1b: Node Keepalive Probing (Pre-Established Only)

The Node sends `FLAG_CONTROL` frames every 100ms while **not** in `Established` state. These keepalives serve two purposes: (1) maintain the NAT/firewall UDP binding on the public internet, and (2) signal liveness to the Hub. **Keepalives stop immediately when the session is established** — tunnel traffic maintains the binding naturally.

```text
Node — node/src/main.rs (both paths: recvmmsg L604-612, io_uring L1045-1052)
├── Guard: !matches!(state, Established) && (now - last_keepalive_ns > 100ms)
├── build_m13_frame(&src_mac, &hub_mac, seq_tx, FLAG_CONTROL)  [protocol.rs:59]
├── sock.send(&ka)  →  tx_count += 1
└── Stops: immediately on transition to NodeState::Established
```

#### Step 2: Node Initiates PQC Handshake (ClientHello)

When the Node receives **any valid M13 frame** from the Hub while in `Registering` state, `process_rx_frame()` returns `RxAction::NeedHandshakeInit`. In practice, this triggers when existing Hub downstream traffic (from other established peers) or the Hub's scheduler output reaches the Node's connected UDP socket. The Node does not wait for a Hub reply to its registration — **any valid M13 frame is sufficient**.

```text
Node — node/src/main.rs + node/src/cryptography/handshake.rs
├── process_rx_frame()                                          [main.rs:118]
│   ├── Validate magic/version                                  [main.rs:134-136]
│   └── matches!(state, Registering) → RxAction::NeedHandshakeInit [main.rs:139-141]
│
├── initiate_handshake()                                        [handshake.rs:22]
│   ├── MlKem1024::generate(&mut OsRng) → (dk, ek)             [handshake.rs:33]
│   │   └── ek = 1568 bytes (ML-KEM-1024 encapsulation key)
│   ├── MlDsa87::key_gen(&mut OsRng) → (sk, pk)                [handshake.rs:37]
│   │   └── pk = 2592 bytes (ML-DSA-87 verification key)
│   ├── OsRng::fill_bytes(&mut session_nonce)                   [handshake.rs:44]
│   │   └── 32 bytes of CSPRNG nonce
│   ├── Build ClientHello payload:                              [handshake.rs:47-52]
│   │   ├── type   = HS_CLIENT_HELLO (0x01) ─── 1 byte
│   │   ├── version = 0x01 ───────────────────── 1 byte
│   │   ├── nonce ────────────────────────────── 32 bytes
│   │   ├── ek (ML-KEM-1024) ─────────────────── 1568 bytes
│   │   └── pk (ML-DSA-87) ──────────────────── 2592 bytes
│   │   Total: 4194 bytes
│   │
│   ├── send_fragmented_udp(sock, ..., payload, flags)          [protocol.rs:163]
│   │   ├── max_chunk = 1402 bytes per fragment
│   │   ├── FragHeader per chunk: msg_id(2) + index(1) + total(1) + offset(2) + len(2) = 8 bytes
│   │   ├── Fragment 0/3: bytes [0..1402]
│   │   ├── Fragment 1/3: bytes [1402..2804]
│   │   └── Fragment 2/3: bytes [2804..4194]
│   │
│   └── Return NodeState::Handshaking {                         [handshake.rs:60-67]
│       dk_bytes, session_nonce,
│       client_hello_bytes, our_pk, our_sk, started_ns
│   }
```

#### Step 3: Hub Processes ClientHello → Builds ServerHello

The Hub's VPP pipeline reassembles the 3 ClientHello fragments, then processes the complete message: encapsulates the shared secret, signs the transcript, and sends the ServerHello response.

```text
Hub — hub/src/main.rs + hub/src/cryptography/handshake.rs
├── VPP Pipeline (per fragment):
│   ├── rx_parse_raw() → classify_route()                      [datapath.rs:24, 190]
│   │   └── FLAG_FRAGMENT | FLAG_HANDSHAKE → NextNode::Handshake
│   └── handle_handshake_packet()                               [main.rs:520+]
│       ├── Parse FragHeader: msg_id, index, total, offset, len [main.rs:526-537]
│       └── Assembler::feed(msg_id, index, total, offset, data) [main.rs:540]
│           └── On fragment 2/3: reassembly complete → returns Vec<u8>
│
├── process_handshake_message(reassembled, pidx, ctx, stats)    [main.rs:551]
│   ├── msg_type = data[0] = HS_CLIENT_HELLO (0x01)            [main.rs:558-564]
│   ├── PeerLifecycle::Handshaking                              [main.rs:565]
│   │
│   ├── process_client_hello_hub(data, &mut seq, now)           [handshake.rs:36]
│   │   ├── Validate: len ≥ 4194, type=0x01, version=0x01      [handshake.rs:41-53]
│   │   ├── Extract session_nonce [2..34]                       [handshake.rs:57-58]
│   │   ├── Extract ek_bytes [34..1602]                         [handshake.rs:59]
│   │   ├── Extract pk_node_bytes [1602..4194]                  [handshake.rs:60]
│   │   ├── ML-KEM-1024: ek.encapsulate(&mut OsRng) → (ct, ss) [handshake.rs:73]
│   │   │   ├── ct = 1568 bytes (ciphertext for Node)
│   │   │   └── ss = 32 bytes (shared secret)
│   │   ├── ML-DSA-87: key_gen(&mut OsRng) → (sk_hub, pk_hub)  [handshake.rs:83]
│   │   ├── transcript = SHA-512(ClientHello || ct)             [handshake.rs:87-90]
│   │   ├── sig_hub = sk_hub.sign(transcript, "M13-HS-v1")     [handshake.rs:92]
│   │   │   └── 4627 bytes (ML-DSA-87 signature)
│   │   ├── Build ServerHello payload:                          [handshake.rs:102-106]
│   │   │   ├── type   = HS_SERVER_HELLO (0x02) ── 1 byte
│   │   │   ├── ct (ML-KEM-1024) ─────────────── 1568 bytes
│   │   │   ├── pk_hub (ML-DSA-87) ───────────── 2592 bytes
│   │   │   └── sig_hub (ML-DSA-87) ──────────── 4627 bytes
│   │   │   Total: 8788 bytes
│   │   │
│   │   └── Return (HubHandshakeState, server_hello_payload)    [handshake.rs:112-119]
│   │       └── HubHandshakeState stores: node_pk, ss, nonce, CH, SH bytes
│   │
│   ├── Transmit ServerHello (UDP path):                        [main.rs:569-590]
│   │   ├── build_fragmented_raw_udp(src_mac, gw_mac, ...)     [handshake.rs:187]
│   │   │   └── 7 fragments × (ETH+IP+UDP + ETH+M13+FragHdr+chunk)
│   │   └── For each fragment:
│   │       ├── slab.alloc() → slab_idx                        [main.rs:580]
│   │       ├── memcpy frame → UMEM[slab_idx × frame_size]     [main.rs:583]
│   │       └── scheduler.enqueue_critical(addr, len)          [main.rs:584]
│   │           └── Critical priority: bypasses BBRv3 pacing
│   │
│   └── peers.hs_sidecar[pidx] = Some(hs_state)               [main.rs:613]
│       └── Stored for Finished processing in next VPP cycle
```

#### Step 4: Node Processes ServerHello → Sends Finished

The Node reassembles the 7 ServerHello fragments, decapsulates the shared secret, verifies the Hub's signature, derives the session key, signs the full transcript, and sends the Finished message.

```text
Node — node/src/main.rs + node/src/cryptography/handshake.rs
├── CQE Loop (per fragment):
│   ├── process_rx_frame() → fragment handling                  [main.rs:195-226]
│   │   ├── Parse FragHeader                                    [main.rs:197-203]
│   │   └── assembler.feed(msg_id, index, total, offset, data)  [main.rs:206-209]
│   │       └── On fragment 6/7: reassembly complete
│   │
│   └── FLAG_HANDSHAKE set → process_handshake_node()           [main.rs:210-214]
│
├── process_handshake_node(reassembled, state)                  [handshake.rs:69]
│   ├── Validate state == Handshaking (extract dk, nonce, CH)   [handshake.rs:74-82]
│   ├── Validate: type=0x02, len ≥ 8788                        [handshake.rs:86-100]
│   ├── Extract ct_bytes [1..1569]                              [handshake.rs:103]
│   ├── Extract pk_hub_bytes [1569..4161]                       [handshake.rs:104]
│   ├── Extract sig_hub_bytes [4161..8788]                      [handshake.rs:105]
│   │
│   ├── ML-KEM-1024: dk.decapsulate(ct) → ss                   [handshake.rs:120-126]
│   │   └── 32-byte shared secret (same as Hub's)
│   ├── transcript = SHA-512(ClientHello || ct)                 [handshake.rs:129-131]
│   ├── pk_hub.verify(transcript, "M13-HS-v1", sig_hub)        [handshake.rs:147]
│   │   └── MITM detection: abort if verification fails
│   │
│   ├── HKDF-SHA-512(salt=nonce, IKM=ss, info="M13-PQC-SESSION-KEY-v1", L=32)
│   │   → session_key (32 bytes)                                [handshake.rs:152-156]
│   │
│   ├── transcript2 = SHA-512(ClientHello || ServerHello)       [handshake.rs:159-161]
│   ├── sig_node = sk_node.sign(transcript2, "M13-HS-v1")      [handshake.rs:172]
│   ├── Build Finished payload:                                 [handshake.rs:179-181]
│   │   ├── type    = HS_FINISHED (0x03) ─── 1 byte
│   │   └── sig_node (ML-DSA-87) ────────── 4627 bytes
│   │   Total: 4628 bytes
│   │
│   └── Return Some((session_key, finished_payload))
│
├── RxAction::HandshakeComplete handling:                       [main.rs:987-1011]
│   ├── send_fragmented_udp(sock, ..., finished, flags)         [main.rs:989-993]
│   │   └── 4 fragments (⌈4628/1402⌉)
│   ├── NodeState::Established {                                [main.rs:998-1005]
│   │   session_key,
│   │   cipher: LessSafeKey::new(AES_256_GCM, &session_key),
│   │   frame_count: 0,
│   │   established_ns: now,
│   │ }
│   └── setup_tunnel_routes(&hub_ip)                            [main.rs:1008]
│       ├── ip route add default dev m13tun0 table 100
│       ├── ip rule add from all lookup 100
│       └── Enables: all IP traffic → TUN → AEAD → UDP → Hub
```

#### Step 5: Hub Processes Finished → Session Established

The Hub reassembles the 4 Finished fragments, verifies the Node's signature over the full transcript, derives the identical session key via HKDF, and installs the AES-256-GCM cipher for bidirectional AEAD.

```text
Hub — hub/src/main.rs + hub/src/cryptography/handshake.rs
├── Fragment reassembly (same VPP path as Step 3)
│   └── Assembler::feed() × 4 → reassembly complete
│
├── process_handshake_message() → HS_FINISHED branch           [main.rs:621]
│   ├── Retrieve hs_state from peers.hs_sidecar[pidx]         [main.rs:622]
│   │
│   ├── process_finished_hub(data, hs_state)                   [handshake.rs:125]
│   │   ├── Validate: type=0x03, len ≥ 4628                   [handshake.rs:129-137]
│   │   ├── Extract sig_node_bytes [1..4628]                   [handshake.rs:141]
│   │   ├── transcript2 = SHA-512(CH || SH)                    [handshake.rs:143-146]
│   │   │   └── Using stored client_hello_bytes + server_hello_bytes
│   │   ├── pk_node.verify(transcript2, "M13-HS-v1", sig_node) [handshake.rs:167]
│   │   │   └── MITM detection: abort if verification fails
│   │   ├── HKDF-SHA-512(salt=nonce, IKM=ss, info="M13-PQC-SESSION-KEY-v1", L=32)
│   │   │   → session_key (32 bytes)                           [handshake.rs:174-177]
│   │   └── Return Some(session_key)
│   │
│   ├── Install session:                                       [main.rs:624-631]
│   │   ├── peers.slots[pidx].session_key = key
│   │   ├── peers.ciphers[pidx] = LessSafeKey::new(AES_256_GCM, &key)
│   │   ├── peers.slots[pidx].frame_count = 0
│   │   ├── peers.slots[pidx].lifecycle = PeerLifecycle::Established
│   │   └── peers.hs_sidecar[pidx] = None  (free handshake state)
│   │
│   └── stats.handshake_ok += 1
│       └── Telemetry: HS:1/0 (ok/fail)
```

#### Step 6: Bidirectional AEAD Tunnel Active

Both sides now have identical AES-256-GCM session keys derived from the same ML-KEM shared secret via HKDF-SHA-512. All subsequent tunnel data is encrypted/authenticated.

```text
Upstream (Node → Hub):
  TUN read → build_m13_frame(FLAG_TUNNEL) → seal_frame(cipher, seq, DIR_NODE_TO_HUB)
  → crypto_ver=0x01 stamped → sock.send() → UDP → Hub
  → Hub rx_parse_raw() → crypto_ver=0x01 → decrypt_out → aead_decrypt_vector()
  → open_frame(cipher, DIR_HUB_TO_NODE) → FLAG_TUNNEL → TunWrite → SPSC → TUN write

Downstream (Hub → Node):
  TUN read → SPSC → tun_read_batch() → seal_frame(cipher, seq, DIR_HUB_TO_NODE)
  → build_raw_udp_frame() → AF_XDP TX → UDP → Node
  → Node CQE (TAG_UDP_RECV_MULTISHOT) → batch decrypt_batch_ptrs()
  → open_frame(cipher, DIR_NODE_TO_HUB) → FLAG_TUNNEL → TunWrite → io_uring write
```

#### Step 7: Failure Recovery

```text
Handshake Timeout (5s):                                         [main.rs:591-601 / 1033-1042]
  NodeState::Handshaking.started_ns + HANDSHAKE_TIMEOUT_NS exceeded
  → Re-send registration (FLAG_CONTROL)
  → Assembler::new() (flush stale fragments)
  → NodeState::Registering (restart from Step 0)

Connection Timeout (30s, io_uring path only):                    [main.rs:782-786]
  Pre-Established + 30_000_000_000 ns elapsed since start
  → Process exits cleanly

Handshake Failure:                                               [main.rs:1012-1014]
  process_handshake_node() returns None
  → RxAction::HandshakeFailed → NodeState::Disconnected
  → On next valid RX frame: Disconnected→Registering auto-transition [main.rs:504-506]

Rekey Trigger:                                                   [main.rs:177-180 / 488-491]
  frame_count ≥ REKEY_FRAME_LIMIT (2³² = 4,294,967,296)
  OR elapsed > REKEY_TIME_LIMIT_NS (3600s = 1 hour)
  → Node: NodeState::Registering → full re-handshake (Step 0)
  → Hub: PeerSlot persists; new handshake overwrites session_key + cipher
  → Zero downtime: old cipher active until new Finished completes
```

---

## VI. Dependencies & Security Posture

M13 relies on an absolute minimum of external crates to reduce the supply chain attack surface.

### Workspace Release Profile (`Cargo.toml`)

```toml
[profile.release]
panic = "abort"      # No unwind tables — binary size reduction, panic = instant exit
lto = true           # Whole-program link-time optimization across all crates
codegen-units = 1    # Maximum optimization (no parallel codegen splitting)
opt-level = 3        # Aggressive optimization
strip = "symbols"    # Strip debug symbols from release binary
```

### Hub & Node Shared Dependencies

| Crate | Version | Subsystem | Hot Path? | Justification |
| --- | --- | --- | --- | --- |
| `libc` | 0.2 | Core I/O | ✅ | `mmap`, `sched_setaffinity`, `poll`, `read`/`write` |
| `ring` | 0.17 | Crypto | ✅ | AES-256-GCM `LessSafeKey` for AEAD seal/open |
| `bytemuck` | 1.14 | Parsing | ✅ | Zero-copy header casting (`derive` feature) |
| `ml-kem` | 0.2 | PQC | ❌ | FIPS 203 ML-KEM-1024 key encapsulation (handshake only) |
| `ml-dsa` | 0.0.4 | PQC | ❌ | FIPS 204 ML-DSA-87 digital signatures (handshake only) |
| `sha2` | 0.10 | PQC | ❌ | SHA-512 for HKDF + transcript hashing (handshake only) |
| `hkdf` | 0.12 | PQC | ❌ | HKDF-SHA-512 session key derivation (handshake only) |
| `rand` | 0.8 | PQC | ❌ | OsRng CSPRNG via `getrandom(2)` (handshake only) |
| `bindgen` | 0.69 | Build | ❌ | Build-time kernel header bindings |

### Hub-Specific Dependencies

| Crate | Version | Subsystem | Hot Path? | Justification |
| --- | --- | --- | --- | --- |
| `libbpf-sys` | 0.6 | Network | ❌ (Init) | Loads XDP/eBPF redirect program at `run_executive()` init |

### Node-Specific Dependencies

| Crate | Version | Subsystem | Hot Path? | Justification |
| --- | --- | --- | --- | --- |
| `io-uring` | 0.7 | Network | ✅ | Kernel 6.12+ `IORING_SETUP_SQPOLL`, `IORING_RECV_MULTISHOT`, PBR |

---

## VII. Zero-Waste Determinism (Static Liveness Protocol)

M13 enforces a strict, zero-waste binary footprint. The architecture mandates that any code failing to mathematically prove its liveness in the compiler's Mid-Level Intermediate Representation (MIR) is inherently adversarial and must be automatically incinerated.

Lexical analysis (`grep`/Bash) is explicitly banned due to macro-expansion blindness. M13 achieves proof of liveness via a custom `rustc` driver and strict compiler lints (`#![deny(dead_code)]`, `#![deny(unused_variables)]`) that traverse the intermediate compiler graphs. This guarantees a pristine topological blueprint for all future hardware migrations.

### 1. MIR Call-Graph Reachability

M13 models function execution as a directed graph $G = (V, E)$, where $V$ represents all functions and $E$ represents invocation edges in the MIR. The protocol computes the transitive closure originating strictly from hardware entry points (e.g., `main`, interrupt vectors, eBPF hooks).

Let $R$ be the set of root execution nodes. A function node $v$ is mathematically live if and only if:
$$v \in Closure(R) \iff \exists \text{ path from } R \text{ to } v$$

Any function $v \notin Closure(R)$ is proven dead by the compiler. The build pipeline automatically aborts, demanding manual developer removal of the phantom execution path.

### 2. HIR Field-Level Memory Validation

Bloated struct definitions waste L1d cache and memory bandwidth. The M13 compiler driver traverses the High-Level Intermediate Representation (HIR) to enforce bidirectional memory liveness.

For every field $f$ within a struct $S$, the compiler must verify two distinct state transitions across the codebase:
* **Write State:** $\exists$ an assignment to $S.f$
* **Read State:** $\exists$ a subsequent load from $S.f$

If $S.f$ is written to but never read, or read but statically initialized without modification, the field is classified as a phantom payload and the compilation panics.

### 3. MIR Semantic Liveness (Def-Use Chains)

M13 executes strict Dataflow Analysis on the MIR control-flow graph to eradicate dead stores and discarded error codes. A variable assignment (Definition) is only mathematically valid if it reaches a subsequent consumer (Use) that influences hardware state (e.g., an `io_uring` submission, an `AF_XDP` ring update, or a hardware DMA register write).

The compiler evaluates the `LiveOut` state for every basic block $n$:
$$LiveOut(n) = \bigcup_{s \in succ(n)} LiveIn(s)$$

If a variable is defined but its state transitions to `StorageDead` before reaching a valid `LiveIn` state of a successor block, the allocation is flagged as a semantic leak.

### 4. Zero-Tolerance Dependency Pruning

The supply chain attack surface is minimized by continuously auditing the AST for phantom external crates. M13 utilizes strict `cargo-udeps` integration at the CI/CD level.

If a crate is declared in `Cargo.toml` but lacks a resolved invocation edge in the lowered AST, the build fails. There are zero waivers for unused dependencies.

---

## VIII. Verification & Validation (V&V) Matrix

"Happy Path" testing is structurally prohibited. M13 must mathematically prove its logical correctness, memory safety, and physical resilience against adversarial physics, cryptographic anomalies, and silicon bottlenecks before Tier-1 flight trials.

Execution of this matrix guarantees the state machine is perfectly deterministic. The V&V Matrix strictly separates logical software proofs from physical silicon validation.

### Tier 1: Core Mathematical Integration

Validates the foundational mathematics and deterministic memory boundaries of the architecture in absolute isolation.

* **Vector:** 80 strict deterministic tests executed via `cargo test` (33 Hub unit, 30 Hub integration, 17 Node unit).
* **Criteria:** Verifies VPP pipeline scatter/gather logic, Galois Field matrix inversions, AES-256-GCM AEAD bit-exactness, wire format parity, and Compile-Time Typestate transitions. Zero allocations permitted in the hot path during execution.

### Tier 2: Namespace Bounded Integration (NetNS E2E)

Validates the **logical packet-processing graph (VPP)** and typestate transitions without RF/cloud variability, utilizing strict Linux Network Namespaces bridged via a synthetic `veth` pair.

* **Vector:** Kernel-isolated Linux `netns` (`ns_node`, `ns_hub`).
* **Criteria:** PQC handshake mathematically converges within **250ms**. Base logical throughput achieves theoretical maximums limited only by DDR4 memory bandwidth. `SIGKILL` on the Node triggers Hub `E_PEER_TIMEOUT` detection within **500ms**, verifying state machine timeout enforcement.

### Tier 3: Cryptographic Fuzzing (`libfuzzer`)

Mathematical proofs of spatial memory safety and algorithmic stability under adversarial mutation.

* **Vector:** `cargo-fuzz` compiling against LLVM libFuzzer.
* **Criteria:** Millions of mutating, adversarial byte arrays injected into `rx_parse_raw()`, `Assembler::feed()`, and `open_frame()`. The AST must mathematically guarantee a `false` or `Drop` return type without triggering timing side-channels, Out-Of-Memory (OOM) conditions, arithmetic panics, or segmentation faults.

### Tier 4: Micro-Architectural Benchmarking (`criterion`)

Instruction-Per-Cycle (IPC) variance tracking and ALU saturation bounds.

* **Vector:** `cargo bench` isolated to CPU Core 0 via `taskset` and CPU affinity pinning.
* **Criteria:** `aead_decrypt_vector` and `classify_route` batches must not regress in CPU cycle cost by **> 2%** across any commit. Any latency regression automatically halts the CI/CD pipeline, enforcing strict cycle-budget invariant bounds.

### Tier 5: Kinetic Survival & Chaos Engineering (CSE)

Validates the logical VPP state machines against Contested Spectrum Environment (CSE) realities.

* **Vector:** `tc netem` applied to Tier 2 virtual interfaces, injecting rigorous Gilbert-Elliott burst-loss models.
* **Criteria:**
* Inject `loss 30%`. Verify Software RLNC/FEC recovers the stream mathematically without triggering TCP `DUP-ACK` storms at the TUN boundary.
* Inject `delay 4s`. Verify MBB Epoch continuity and PQC Handshake survival.
* Inject `delay 6s`. Verify deterministic `HANDSHAKE_TIMEOUT_NS` correctly resets the FSM to `Disconnected`.
* Inject 100,000 duplicated `seq_id` payloads. Verify `replay_drops` atomic counter increments perfectly via the RFC 6479 bitmask with CPU utilization delta **< 1%**, proving algorithmic DoS immunity.



### Tier 6: Hardware-In-The-Loop (HITL) Silicon Proof

Validates the **true physical pipeline** (PCIe, DMA, AXI Bus, SMMU) against physical RF degradation and hardware exhaustion.

* **Vector:** Physical K26 SOM connected via physical Gigabit Ethernet/WiFi to an RF channel emulator.
* **Criteria:** Validates BBRv3 EDT pacing against real hardware queue backpressure. Validates IEEE 1588 hardware timestamping accuracy from the physical Gigabit Ethernet MAC (GEM). Proves zero CPU thermal throttling and zero dropped packets at the physical NIC ring buffers under sustained 50 Mbps Bandwidth-Delay Product (BDP) micro-bursts.

---

## IX. Project Documents

| Document | Purpose |
|----------|---------|
| [TODO.md](TODO.md) | Technical debt ledger, sprint cards, telemetry matrix, V&V tiers |
| [OBSERVATIONS.md](OBSERVATIONS.md) | Quantified sprint metrics, cross-sprint comparison tables, measurement formulas |
| [PROTOCOL.md](PROTOCOL.md) | Engineering workflow: pre-sprint research, execution, debugging, post-sprint documentation |
