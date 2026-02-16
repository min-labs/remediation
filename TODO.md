# ROADMAP

| Sprint | Sub-system | Feature | Physics & Architectural Rationale |
| --- | --- | --- | --- |
| **1** | **Memory & Topology** | **Thread Isolation & NUMA** | **Foundation.** Eradicates the monolithic "God Loop". Establishes the 64MB HugePage Arena, 128-byte padded lock-free SPSC rings, and NUMA node pinning to eliminate AXI/UPI bus traversal latency. |
| **2** | **Codebase Ascension** | **Datapath Sanitization & `UmemSlice**` | **Structural Integrity.** Eradicates all raw pointer arithmetic via bounds-checked `UmemSlice`. Replaces hardcoded IPs/Subnets with dynamic ENV configurations. Eradicates hot-path syscalls by gating `eprintln!`. |
| **3** | **Zero-Cost Logic** | **Typestate FSM (ZSTs)** | **ALU Protection.** Replaces runtime enums with Rust Zero-Sized Types. Eradicates branch predictor misses in the hot loop by enforcing protocol state transitions entirely at compile-time. |
| **4** | **Kernel Bypass** | **`io_uring` PBR + USO** | **Syscall Annihilation.** Maps Sprint 1's Arena to Kernel 6.12+ Provided Buffer Rings. Replaces `virtio_net_hdr` traps with Userspace Segmentation Offload to prevent IP fragmentation over RF. |
| **5** | **Stateful Security** | **Anti-Replay, MBB, Keepalives** | **Perimeter Defense.** RFC 6479 bitmask rejects DoS replays in  cycles (wires `replay_drops`). Make-Before-Break guarantees 0ms stream interruption during keygen. Active Keepalives defeat CGNAT deadlocks. |
| **6** | **Symmetric Scaling** | **RSS & UDP Port Spraying** | **Hardware Load Balancing.** Mutates outer UDP Source Port via inner IP hash. Forces the NIC Toeplitz hardware hash to perfectly spray flows across all A53/x86 CPU cores. |
| **7** | **Compute Saturation** | **AES Instruction Pipelining** | **ALU Saturation.** Discards sequential crypto batches. Implements 4x/8x unrolled, interleaved AES-NEON/AES-NI assembly to eradicate CPU execution port latency bubbles. |
| **8** | **Asymmetric Armor** | **eBPF PQC Rate-Limiting** | **The Outer Shield.** Implements eBPF XDP/Socket token buckets to drop spoofed `ClientHello` floods at L2, physically protecting the 120µs ML-DSA verification path from network-borne CPU exhaustion. |
| **9** | **Distributed Trust** | **CBOR MicroCerts & Swarm PKI** | **Zero-Trust.** Wires `_now_ns` eviction parameters. Implements offline Root CA validation, the 6-state Peer Lifecycle, and Gossip-based Bloom Filter revocation arrays executing in  time. |
| **10** | **Kinetic Resilience** | **Merkle Integrity & Append-Log** | **State Survival.** Uses Append-Only logs to prevent eMMC Write Amplification. Anchors FSM state to a SHA-256 Merkle Tree to mathematically detect physical flash-memory tampering post-reboot. |
| **11** | **Congestion Physics** | **BBRv3 Math & EDT Pacing** | **Bufferbloat Prevention.** Wires `bbr_btlbw_kbps`, `bbr_phase`, and `_rtt_est`. Drives the Earliest Departure Time (EDT) Token Bucket precisely at the BDP limit calculated by BBRv3 math. |
| **12** | **Isochronous Physics** | **HW Timestamps &  ROB** | **TCP Cwnd Protection.** Wires `_jbuf_depth` ABI parameters. Pulls IEEE 1588 PTP timestamps directly from MAC registers to sequence out-of-order orbital arrivals. Enforces strict playout deadlines before TUN injection. |
| **13** | **Algebraic Erasure** | **Software RLNC & FEC (SIMD)** | **Stochastic Recovery.** Wires `_offset` for reassembly. Executes Galois Field  matrices via x86_64 AVX2 / ARM NEON split-nibble vector shuffling. Serves as the Software Golden Reference Model. |
| **14** | **Heterogeneous Bond** | **Multi-path Scheduler** | **Apex Scale.** Active/Active bonding of Starlink, AST, and Kuiper. Shifts Sprint 13's encoded RLNC blocks proportionally to instantaneous RTT and path capacities. |
| **15** | **Verification & Validation (V&V)** | **Tiers 2-5: E2E, Fuzz, Perf, Chaos** | **Absolute Proof.** Executes Namespace E2E testing, `libfuzzer` memory-safety proofs, performance regression gates, and strict Contested Spectrum Environment (CSE) Gilbert-Elliott loss models. |
| **16** | **Compiler Ascendancy** | **LLVM PGO / BOLT** | **L1i Cache Perfection.** Instruments the binary, processes Sprint 15's CSE workloads, and recompiles for perfect branch-prediction assembly alignment via LLVM Basic Block Optimization. |
| **17** | **Silicon Ascension** | **FPGA PL Offload (RLNC+AES)** | **The Hardware Apex.** Synthesizes Sprint 13 and Sprint 7's protocol into AXI4-Stream FPGA Programmable Logic. Executes at literal hardware line-rate, bypassing the ARM CPU entirely via zero-copy DMA. |

---

**CURRENT PROGRESS (Pre-Sprint 1):**
The implementation is a structural illusion. It masquerades as a kernel-bypass, zero-copy transport architecture, yet its physical execution model relies on synchronous Virtual File System (VFS) blocking, catastrophic algorithmic  memory fragmentation, double-precision floating-point ALU pollution, and purely scalar cryptographic loops wrapped in fake "batch" iterators.

If this binary is flashed to flight hardware and subjected to a Contested Spectrum Environment (CSE) or gigabit line-rate micro-bursts, the CPU execution ports will starve, the L1 caches will thrash, and the Node will suffer instantaneous memory exhaustion (OOM) within milliseconds.

Below is the uncompromising, fiduciary-grade technical debt ledger.

---

# M13 REMEDIATION ROADMAP (R-SERIES)

### ✅ SPRINT R-01: HARDWARE DETERMINISM ENFORCEMENT (COMPLETED 2026-02-15)

**Scope:** Eradicate all software fallback paths from the Hub's AF_XDP datapath initialization. Enforce physical hardware binding at boot or `SIGABRT`.

**Files Modified:**

| File | Action | Summary |
| --- | --- | --- |
| `hub/src/network/bpf.rs` | **OVERWRITTEN** | `load_and_attach` returns `Self` (was `Option<Self>`). `XDP_FLAGS_SKB_MODE` import and fallback chain eradicated. `M13_SIMULATION` env check eradicated. `prog.is_null()` / `map.is_null()` null-pointer guards added. RLIMIT_MEMLOCK fallback to `RLIM_INFINITY` retained with architectural justification (policy scope, not physics degradation). |
| `hub/src/network/xdp.rs` | **OVERWRITTEN** | `create_dummy_engine` (41-line mock allocator) eradicated. `M13_SIMULATION` env checks (4 occurrences) eradicated. 4KB `mmap` fallback eradicated — `MAP_HUGETLB \| MAP_POPULATE \| MAP_LOCKED` strictly enforced. `XDP_COPY` fallback eradicated — `XDP_ZEROCOPY \| XDP_USE_NEED_WAKEUP` strictly enforced. `kick_tx` now allows transient `EAGAIN`/`EBUSY`/`ENOBUFS`, fatals only on `ENXIO`/`EBADF`. HugePage error message corrected to `hugepages=600`. |
| `hub/src/main.rs` | **PATCHED (2 blocks)** | **Patch 1:** `udp_mode` / `M13_LISTEN_PORT` worker-count gate removed. All workers are XDP-backed. **Patch 2:** `Option<BpfSteersman>` unwrap with `-1` fallback replaced by direct `BpfSteersman::load_and_attach()` → `Self`. |

**Eradicated Constructs:** `create_dummy_engine`, `M13_SIMULATION`, `XDP_FLAGS_SKB_MODE`, `XDP_COPY`, `MAP_ANONYMOUS`-only mmap fallback, `Option<BpfSteersman>`, `udp_mode` worker gate.

**Added Constructs:** `MAP_LOCKED`, `XDP_ZEROCOPY`/`XDP_USE_NEED_WAKEUP` constants, `prog.is_null()`/`map.is_null()` guards, transient errno handling in `kick_tx`.

> **⚠ BREAKING CHANGE:** `M13_SIMULATION=1` no longer works. Developers must use Linux Network Namespaces + `veth` pairs with native AF_XDP for local testing.

---

### ✅ SPRINT R-02A: DATAPATH VFS DECOUPLING — HUB (COMPLETED 2026-02-15)

**Scope:** Remove VFS syscalls (`libc::read`/`libc::write` on TUN fd) from the Hub's AF_XDP datapath hot-loops. Introduce SPSC lock-free rings for inter-thread TUN I/O communication.

**Files Modified:**

| File | Action | Summary |
| --- | --- | --- |
| `hub/src/engine/spsc.rs` | **NEW** | 142-line SPSC lock-free ring buffer. 128-byte `CachePadded` false-sharing immunity. DPDK-style local head/tail caching. Batch `push_batch`/`pop_batch` with single Release barrier per batch. |
| `hub/src/engine/mod.rs` | **PATCHED** | Registered `pub mod spsc`. |
| `hub/src/network/mod.rs` | **PATCHED** | Added `PacketVector::capacity()`. Added 4 `Option<&mut Producer/Consumer>` SPSC handles to `GraphCtx`. |
| `hub/src/network/datapath.rs` | **PATCHED** | Rewrote `tun_write_vector` (SPSC push path + VFS fallback). Rewrote `tun_read_batch` (SPSC pop + free slab lifecycle + VFS fallback). |
| `hub/src/main.rs` | **PATCHED** | Created 4 SPSC rings (256-deep). Spawned `tun_housekeeping_thread` on isolated core. `worker_entry` accepts `Option` SPSC handles. `execute_subvector` conditional slab-free. Both `GraphCtx` constructions populated with SPSC fields. |

**Added Constructs:** `SpscRing<T>`, `Producer<T>`, `Consumer<T>`, `make_spsc()`, `tun_housekeeping_thread`, `PacketVector::capacity()`, 4 SPSC fields in `GraphCtx`.

**Self-Audit:**
- **Over-corrections:** None. VFS fallback paths preserved. Non-tunnel mode unaffected.
- **Under-delivery:** TUN HK thread is scaffolded (drains rings, returns slab indices) but does not perform actual `libc::read`/`libc::write` — requires UMEM base pointer sharing (deferred).

---

### ✅ SPRINT R-02B: NODE `io_uring` REACTOR INTEGRATION (COMPLETED 2026-02-15)

**Scope:** Replace the Node's legacy `recvmmsg`/`sendmmsg` VFS event loop with a kernel-bypass `io_uring` reactor using `IORING_SETUP_SQPOLL` and Provided Buffer Rings (PBR).

**Files Modified:**

| File | Action | Summary |
| --- | --- | --- |
| `node/Cargo.toml` | **PATCHED** | Added `io-uring = "0.7"` — safe Rust bindings for `SQPOLL` + PBR. |
| `node/src/network/mod.rs` | **PATCHED** | Registered `pub mod uring_reactor`. |
| `node/src/network/uring_reactor.rs` | **NEW** | 220-line io_uring reactor. HugeTLB mmap arena, PBR registration via `SYS_io_uring_register`, multishot recv arming, BID recycle, staged TUN read/write/UDP send SQE helpers. `arena_base_ptr()` accessor for in-place frame construction. |
| `node/src/main.rs` | **PATCHED (3 blocks)** | **Patch 1:** `main()` calls `run_uring_worker()` instead of `run_udp_worker()`. **Patch 2:** `run_udp_worker` marked `#[allow(dead_code)]` as legacy fallback. **Patch 3:** Complete `run_uring_worker()` function — UringReactor init, CQE three-pass loop (Pass 0: drain+classify, Pass 1: batch AEAD decrypt, Pass 2: RxAction dispatch), state machine preservation. |

**Added Constructs:** `UringReactor`, `arm_multishot_recv()`, `stage_tun_write()`, `stage_udp_send()`, `arm_tun_read()`, `run_uring_worker()`, CQE tag constants (`TAG_UDP_RECV_MULTISHOT`, `TAG_TUN_READ`, `TAG_TUN_WRITE`, `TAG_UDP_SEND_TUN`, `TAG_UDP_SEND_ECHO`).

**Runtime Verification (2026-02-15):**
- Hub (remote): `RX:990 TX:963 TUN_R:963 TUN_W:979 AEAD:978/0 HS:1/0 Slab:1539/8192 Peers:1/1`
- Node (local): `RX:983 TX:986 TUN_R:982 TUN_W:965 AEAD_OK:965 FAIL:0 State:Est`
- Zero AEAD failures. Bidirectional tunnel operational. PQC handshake completed (HS:1/0).

> **⚠ NOTE:** `run_udp_worker()` is preserved with `#[allow(dead_code)]` as a legacy VFS fallback. It can be re-activated by changing the call in `main()`.

---

### ✅ SPRINT R-03: FPU POLLUTION ERADICATION (COMPLETED 2026-02-15)

**Scope:** Eradicate IEEE 754 double-precision floating-point (`f64`) from the Hub's `JitterEstimator` in the datapath hot-loop. Replace with Q60.4 fixed-point integer math per RFC 3550 §A.8.

**Files Modified:**

| File | Action | Summary |
| --- | --- | --- |
| `hub/src/engine/protocol.rs` | **PATCHED** | `JitterEstimator.jitter_ns: f64` → `jitter_q4: u64`. EWMA update rewritten: `wrapping_sub(jitter_q4 >> 4) + |D|`. `JBufEntry` gained `#[derive(Clone, Copy)]` + `Default`. All jitter buffer methods `#[inline(always)]`. |
| `PROTOCOL.md` | **PATCHED** | §1.3 hardware constraint corrected: `Cortex-A76` → `Cortex-A53` (Kria K26 SOM). §4.4 Local Backup added. |

**Eradicated Constructs:** `f64` type, `/ 16.0` FP division, `as f64` cast, `/ 1000.0` FP division.

**Added Constructs:** `jitter_q4: u64` (Q60.4), `wrapping_sub`/`wrapping_add`, `abs_diff`, `Default for JBufEntry`.

**Self-Audit:**
- Zero `f64` or `f32` in Hub workspace (verified by `grep`)
- API surface unchanged: `update()`, `get()`, `jitter_us()` signatures identical
- No live deployment — mathematical equivalence replacement, server destroyed after R-02
- Live telemetry validation deferred to next sprint with server

---

### ✅ SPRINT R-04: SPEC-TO-SOURCE ALIGNMENT & DEAD CODE ERADICATION (COMPLETED 2026-02-16)

**Scope:** Align codebase to PROTOCOL.md spec. Fix 2 spec deviations (DEFECT β: closure-based `send_fragmented_udp`, DEFECT ε: `GraphCtx` observability). Remove dead code (`Assembler::new()`). Relocate integration tests. Add `Up:Xs` session duration telemetry. Fix `ETH_P_M13.to_be()` ethertype comparison bug.

**Files Modified:**

| File | Action | Summary |
| --- | --- | --- |
| `node/src/engine/protocol.rs` | **PATCHED** | `send_fragmented_udp` → closure-based `emit: FnMut(&[u8])` (DEFECT β) |
| `node/src/cryptography/handshake.rs` | **PATCHED** | Updated call site for closure pattern |
| `node/src/main.rs` | **PATCHED** | Updated 2 call sites for closure pattern. Added `Up:Xs` to periodic + shutdown telemetry (recvmmsg + io_uring paths). |
| `hub/src/network/mod.rs` | **PATCHED** | `GraphCtx` gained `hexdump: &mut HexdumpState` + `cal: TscCal` (DEFECT ε) |
| `hub/src/main.rs` | **PATCHED** | Updated 2 `GraphCtx` construction sites. Added `worker_start_ns` + `Up:Xs` to periodic + shutdown telemetry. |
| `hub/src/engine/protocol.rs` | **PATCHED** | Removed dead `Assembler::new()`. Added safety doc + `#[allow(clippy::not_unsafe_ptr_arg_deref)]`. |
| `hub/src/network/datapath.rs` | **PATCHED** | Fixed `ethertype == ETH_P_M13.to_be() \|\| ethertype == 0x88B5` → `ethertype == ETH_P_M13` (clippy: equal expressions). |
| `hub/tests/pipeline.rs` → `tests/integration.rs` | **RELOCATED** | Root-level workspace member crate `m13-tests`. |

**Eradicated Constructs:** `Assembler::new()` dead code, `ETH_P_M13.to_be()` redundant byte-swap, DEFECT β (parameter-coupled TX), DEFECT ε (blind `GraphCtx`).

**Added Constructs:** `Up:Xs` telemetry counter (Hub `worker_start_ns` + Node `established_ns`/`start_ns`), `#[allow(clippy::not_unsafe_ptr_arg_deref)]` with safety doc on `Assembler`.

**Self-Audit:**
- `cargo clippy`: 1 genuine bug fixed (`ETH_P_M13.to_be()`), 4 raw-pointer lints suppressed with safety documentation
- Zero `Assembler::new()` call sites (verified by `grep`)
- `send_fragmented_udp` signature matches PROTOCOL.md spec
- 84 tests passing (Hub: 35, Node: 19, Integration: 30)
- Live deployment: 2 sessions (R-04A: ~16min, R-04B: 482s), 274,780 AEAD ops, zero failures
- Known issue: ClientHello fragment retransmission — fires once, retries after 5s timeout. Fix deferred.


## Remediation Sprint R-05: Asynchronous Control Plane Offload (MBB)

* **Target Defect:** Node `process_handshake_node` (HoL Blocking via Synchronous PQC Lattice Math).
* **Physics & Architectural Rationale:** ML-DSA-87 and ML-KEM-1024 require Number Theoretic Transform (NTT) polynomial multiplications. On an ARM Cortex-A53, these execute in  to  clock cycles ( to  milliseconds). Executing this inline halts the datapath thread for . At 100 Mbps, this yields  of queued packets, overflowing hardware rings and destroying the isochronous playout SLA.
* **Implementation Method (CS/Tech):**
1. Pin a dedicated Cryptographic Control Plane thread to Core 0 (Housekeeping).
2. When the Datapath receives a `ServerHello`, it pushes the `UmemSlice` pointer to an SPSC Control Ring.
3. The Datapath thread operates a Make-Before-Break (MBB) State Machine: it continues to encrypt and route the existing Established video/telemetry stream at line-rate while the new key generates asynchronously in the background.
4. When Core 0 finishes the NTT transforms, it pushes the new session key back via the return SPSC ring. The datapath atomically swaps the cipher pointer in  cycles utilizing RCU (Read-Copy-Update) semantics without dropping a single packet.



## Remediation Sprint R-06: SIMD Interleaved Cryptographic Pipelining

* **Target Defect:** Hub & Node `encrypt_batch_ptrs` (Sequential Cryptographic ALU Bubbles).
* **Physics & Architectural Rationale:** Calling a scalar AES function in a loop (`for j in 0..4`) starves the CPU. ARMv8 Cryptographic Extensions (`AESE`, `AESMC`) have a 3-cycle hardware execution latency but a 1-cycle throughput. Sequential execution forces the ALU to stall for 2 cycles out of every 3 waiting for the AES round dependency to resolve, achieving exactly 33% of theoretical silicon throughput.
* **Implementation Method (CS/Tech):**
1. Discard the `ring` crate for the hot path. You must drop down to `core::arch::aarch64` NEON intrinsics.
2. Load the state vectors of 4 *independent* network packets into 4 discrete 128-bit vector registers (`v0-v3`, `v4-v7`, `v8-v11`, `v12-v15`).
3. Interleave the AES instructions: `AESE v0, vKey; AESE v4, vKey; AESE v8, vKey; AESE v12, vKey`.
4. By the time `v12` is dispatched, `v0` has completed its 3-cycle hardware latency and is ready for the `AESMC` step. The instruction pipeline is now 100% saturated with zero latency bubbles. Performance mathematically quadruples.



## Remediation Sprint R-07: Userspace Segmentation Offload (USO) MTU Slicer

* **Target Defect:** Node `tun_file.read` (IP Fragmentation over RF).
* **Physics & Architectural Rationale:** Sending a 1562-byte frame across a 1500 MTU WiFi link forces the kernel to execute software IP fragmentation. The probability of losing a fragmented packet scales geometrically: . A single lost 62-byte fragment destroys the entire 1562-byte payload, triggering severe TCP retransmissions.
* **Implementation Method (CS/Tech):**
1. Set the TUN MTU to  (Generic Receive Offload - GRO).
2. The datapath reads massive 64KB TCP super-frames from the kernel.
3. The datapath encrypts the 64KB payload in bulk (vastly superior SIMD vectorization efficiency).
4. Implement USO: Mathematically slice the ciphertext into perfectly sized 1380-byte chunks entirely in userspace using pointer offsets (`start = i * 1380`).
5. Prepend the 62-byte M13 header to each 1380-byte chunk, updating the inner IP header checksum using RFC 1624 differential math (to save cycles). Total wire footprint per frame:  bytes. Zero kernel IP fragmentation occurs.



## Remediation Sprint R-08:  GHASH Anti-Replay Shield

* **Target Defect:** Hub & Node `decrypt_one` (Asymmetric CPU DoS via Unfiltered Replays).
* **Physics & Architectural Rationale:** AES-GCM tag verification requires Galois Hash (GHASH) carry-less multiplications (`PMULL`). If an adversary captures a legitimate frame and replays it 1,000,000 times at line-rate, the datapath will execute 1,000,000 GHASH authentications before discarding them due to tag/nonce rejection. This burns billions of cycles, starving legitimate telemetry.
* **Implementation Method (CS/Tech):**
1. Implement the RFC 6479 64-bit sliding window bitmask using a single `u64`.
2. Compute  using `wrapping_sub`.
3. If , shift the mask left by  and set .
4. If , evaluate `(window >> \Delta) & 1`.
5. If the packet is a mathematical replay, drop it via an arithmetic branchless check executing in  (`SUB`, `LSR`, `AND`) before a single cryptographic instruction is issued.



## Remediation Sprint R-09: Netlink/Rtnetlink Native ABI Router

* **Target Defect:** Node `setup_tunnel_routes` (L1i Cache Annihilation via Subprocess Spawning).
* **Physics & Architectural Rationale:** `std::process::Command::new("ip")` executes `fork()` (TLB shootdown, page table cloning) and `execve()` (ELF binary loading, L1i cache flushing). Loading `ip` or `tc` binaries consumes up to . If routing reconverges during an RF link flap, the datapath's  deterministic deadline is completely obliterated.
* **Implementation Method (CS/Tech):**
1. Eradicate all `Command::new` shell subprocesses.
2. Open an `AF_NETLINK` socket mapped to the `NETLINK_ROUTE` protocol.
3. Construct binary C-structs (`nlmsghdr`, `rtmsg`, `ifinfomsg`, `tcmsg`). Use the `bytemuck` crate to zero-cost cast the Rust structs into `&[u8]` byte arrays.
4. Serialize the structs directly into memory and fire via `libc::sendto()`. Modifying routing tables now consumes  with zero instruction cache eviction.



## Remediation Sprint R-10: HugePage DMA Cache Alignment

* **Target Defect:** Node `main.rs` (L1d Cache Thrashing via Colossal Stack Arrays).
* **Physics & Architectural Rationale:** Declaring `rx_bufs: [[u8; 2048]; 64]` places  of memory directly on the execution stack. The Cortex-A53 L1 Data Cache (L1d) is exactly ****. Iterating over the stack mathematically guarantees a 100% cache miss rate. Fetching from DDR4 penalizes the CPU by  cycles per access, permanently stalling the vector processing pipeline.
* **Implementation Method (CS/Tech):**
1. Eradicate multidimensional stack arrays. Packet buffers must never live on the stack.
2. Map the buffers directly into the NUMA-aligned `MAP_HUGETLB | MAP_POPULATE` HugePage Arena.
3. Align the base addresses to 64-byte boundaries (`#[repr(align(64))]`), ensuring that packet headers perfectly align with hardware cache lines. This allows the CPU hardware prefetcher (`PRFM`) to pipeline RAM accesses deterministically ahead of the ALU.



## Remediation Sprint R-11: Typestate Zero-Sized Types (ZST) Segregation

* **Target Defect:** Node `NodeState` (Branch Predictor Collapse via Runtime FSM Enum Bloat).
* **Physics & Architectural Rationale:** Rust enums are sized to their largest variant. `NodeState` contains multiple `Vec<u8>` arrays (PQC keys), inflating the struct to hundreds of bytes. In the `process_rx_frame` hot-loop, checking `matches!(state, ...)` forces the CPU to load this massive struct into L1d cache, evicting network payloads. Under stochastic RF packet loss, branch predictions will fail, flushing the instruction pipeline for a 15-cycle penalty per miss.
* **Implementation Method (CS/Tech):**
1. Eradicate data-carrying enums from the hot path. Define states as Zero-Sized Types (ZSTs): `struct Disconnected; struct Handshaking; struct Established { cipher: *const LessSafeKey };`.
2. Implement Compile-Time Typestates utilizing generics: `fn process_rx_frame<S: State>(node: &mut Node<S>)`. State transitions consume `self` and return a new type.
3. Cryptographic state buffers must be segregated to a slow-path memory arena. The Hot Loop must only possess an 8-byte pointer footprint. Branch evaluation is mathematically eradicated from the emitted `.text` assembly.



## Remediation Sprint R-12: Wait-Free Signal Handlers

* **Target Defect:** Node `nuke_cleanup_node` (Unrecoverable Deadlock in Asynchronous Signal Handlers).
* **Physics & Architectural Rationale:** `std::sync::Mutex` utilizes `futex` syscalls and is **not async-signal-safe or panic-safe**. If the panic hook (or `SIGINT`) executes while the datapath thread holds the `Mutex` lock, the panic hook attempts to acquire the exact same lock, resulting in an infinite ABBA deadlock. The drone becomes an unrecoverable zombie.
* **Implementation Method (CS/Tech):**
1. Eradicate `Mutex<String>`.
2. Replace it with a lock-free `std::sync::atomic::AtomicU32`.
3. Upon network initialization, convert the Hub IPv4 address string to a 32-bit integer: `let ip_u32 = u32::from_be_bytes(ip.octets());` and store it via `Ordering::Release`.
4. The signal handler reads the atomic integer utilizing `Ordering::Acquire`, recreates the IPv4 string via stack-allocated formatting (`format!("{}.{}.{}.{}", ...)`), and executes the Netlink teardown without acquiring a single thread lock or `futex`. Absolute wait-free teardown execution is guaranteed.



## Remediation Sprint R-13: Branchless Vectorized IP Checksum Folding

* **Target Defect:** Hub `ip_checksum` (Toy-Grade Mathematics).
* **Physics & Architectural Rationale:** A `while i + 1 < data.len()` loop doing byte-by-byte shifting creates false loop-carried dependencies, fails to saturate the ALU's 64-bit datapaths, and forces continuous branch condition evaluations on a fixed-size header.
* **Implementation Method (CS/Tech):**
1. The IPv4 header is a fixed 20 bytes. Cast the slice into five 32-bit integers via `core::ptr::read_unaligned::<[u32; 5]>`.
2. Execute 5 parallel scalar additions (`ADD`).
3. Fold the 32-bit carry overflows into a 16-bit word branchlessly: `sum = (sum & 0xFFFF) + (sum >> 16); sum = (sum & 0xFFFF) + (sum >> 16); return !sum as u16;`. Total execution drops from  instructions to exactly  instructions.



## Remediation Sprint R-14: Hardware Trailing-Zero Intrinsic Iteration

* **Target Defect:** Hub `RxBitmap::drain_losses` ( Branch Predictor Failure).
* **Physics & Architectural Rationale:** Iterating 512 times to check individual bits (`if bit == 0`) destroys the Branch History Table (BHT). Because RF packet drops are stochastic, the BHT will guess incorrectly continuously, triggering instruction pipeline flushes.
* **Implementation Method (CS/Tech):**
1. Iterate solely over the 64-bit words of the bitmap array.
2. To find lost packets (zero bits), invert the 64-bit word (`let missing = !word;`).
3. Utilize hardware intrinsics (compiles down to `RBIT` + `CLZ` on ARM, `TZCNT` on x86) to instantly find the index of the missing packet in  time: `let bit_idx = missing.trailing_zeros();`.
4. Clear the lowest set bit branchlessly using the BLSR instruction: `missing &= missing - 1;`. Repeat until `missing == 0`. The loop executes exactly  times (where  is the number of dropped packets).



## Remediation Sprint R-15: `UmemSlice` Memory Safety Algebra

* **Target Defect:** Hub `rx_parse_raw` (Unbounded Pointer Arithmetic).
* **Physics & Architectural Rationale:** Blind, unverified pointer offset calculation: `unsafe { ctx.umem_base.add(desc.addr as usize + m13_off as usize) }` based on unauthenticated network payloads allows a forged packet to read/write arbitrary physical memory mapped via DMA, instantly panic-crashing the Hub or breaking zero-trust isolation.
* **Implementation Method (CS/Tech):**
1. Define a secure ZST wrapper: `pub struct UmemSlice<'a> { ptr: NonNull<u8>, len: usize, _marker: PhantomData<&'a mut [u8]> }`.
2. The constructor executes exactly ONE mathematical bounds check: `assert!(offset + len <= UMEM_SIZE)`.
3. Because the struct internally guarantees the invariant, LLVM is mathematically proven to safely elide all subsequent slice boundary checks (`[..]`) inside the hot loop. This achieves zero-cost spatial memory safety while enforcing memory isolation between L2 tenants.

---

### P0 FATAL DEBT: OS PHYSICS & KINETIC SURVIVAL

#### [DEBT-P0-01] The `io_uring` Contradiction & VFS Syscall Avalanche (Node & Hub)

**Location:** Node `main.rs` (`run_udp_worker`) and Hub `datapath.rs` (`tun_read_batch`)
**The Defect:** Your topology claims `io_uring` Multishot ingest and `AF_XDP` to bypass the VFS. Instead, your code implements a monolithic `loop {}` that synchronously executes `libc::recvmmsg`, `tun_file.read()`, and `libc::sendmmsg` via legacy POSIX file descriptors.
**The CS/Physics Reality:**

* A Ring 3 (Userspace) to Ring 0 (Kernel) context switch (`SVC` instruction) on an ARM Cortex-A53 consumes ** to ** per invocation to flush the pipeline, preserve register state, acquire VFS spinlocks, and traverse `sk_buff` structs.
* Your Node spin-loop invokes 4 VFS syscalls per iteration:  of pure execution stall simply transitioning CPU privilege states.
* At 1 Gbps, a 1500-byte MTU frame arrives every ****. A 64-byte control frame arrives every ****.
* **Mathematical Proof of Failure:** Your static loop overhead () exceeds the inter-packet arrival time of control bursts by a factor of 15. The kernel's `sk_rmem_alloc` will instantaneously breach your `SO_RCVBUFFORCE` limits, triggering localized hardware tail-drops and TCP `cwnd` collapse.
**The Mandate (Sprint 1 & 4):** Eradicate `libc::*mmsg` and `File::read/write`. Map your Sprint 1 HugePage Arena to Kernel 6.12+ `io_uring` Provided Buffer Rings (PBR). You must utilize `IORING_SETUP_SQPOLL` to offload kernel polling to a dedicated hardware thread, using `IORING_RECV_MULTISHOT` to DMA ingest WiFi packets directly into the Arena with **zero** context switches.

#### [DEBT-P0-02] Algorithmic DoS via Unbounded Heap Allocation ( TLB Exhaustion)

**Location:** Node & Hub `engine/protocol.rs` (`Assembler::feed`) and Node `send_fragmented_udp`
**The Defect:** Reassembling RF fragments by dynamically allocating heap memory via `Vec::with_capacity(total as usize * 1444)` inside a `HashMap<u16, AssemblyBuf>`.
**The CS/Physics Reality:**
This is a catastrophic Memory Exhaustion / Denial of Service vulnerability. The parameters `msg_id` and `total` are extracted directly from untrusted, unauthenticated network payloads (outside the AEAD cryptographic envelope).

* An adversary listening on the local WiFi 7 fronthaul broadcasts spoofed `ETH_P_M13` frames with the `FLAG_FRAGMENT` bit active.
* Sweeping `msg_id` from  to  and setting `total = 255`, the attacker forces your Node to unconditionally execute: `Vec::with_capacity(255 * 1444)`.
*  per `msg_id`.
*  of RAM allocation requests.
* The K26 SOM has 4GB of physical DDR4. The Linux OOM killer will brutally terminate the M13 Node process within milliseconds. Furthermore, allocating vectors zeroes out the memory page, consuming massive memory bus bandwidth before `copy_from_slice` overwrites it.
**The Mandate (Sprint 1 & 13):** The global allocator (`malloc`/`jemalloc`) is strictly prohibited post-boot. The `Assembler` must utilize a statically pre-allocated HugePage Arena matrix. It must employ an  XOR-folding hash mapping for `msg_id` slot resolution.

#### [DEBT-P0-03] Head-of-Line (HoL) Blocking via Synchronous PQC Lattice Math

**Location:** Node `cryptography/handshake.rs` (`process_handshake_node`) & Hub (`process_client_hello_hub`)
**The Defect:** Evaluating ML-DSA-87 signatures and ML-KEM-1024 decapsulation synchronously inside the main datapath packet-processing thread.
**The CS/Physics Reality:**
ML-DSA-87 verification and ML-KEM mathematics are computationally catastrophic Number Theoretic Transform (NTT) polynomial operations. On a Cortex-A53, these algorithms consume  to  clock cycles (** to  milliseconds**).

* By executing this inline, the datapath thread ceases pulling from the hardware NIC/UDP Socket for  milliseconds.
* Assuming a modest 100 Mbps video telemetry stream, a  ms blackout yields  KB of queued packets. This instantly blows past hardware NIC ring limits, causing tail-drops, triggering TCP BBR to crash its `cwnd` (Congestion Window), and destroying the isochronous playout SLA.
**The Mandate (Sprint 5 & 9):** Asymmetric cryptography MUST NOT execute on the Datapath Thread. PQC must be asynchronously offloaded to a Control Plane thread (Core 0) via SPSC rings. The datapath must continue routing existing Established flows (Make-Before-Break paradigm) while the key-exchange resolves in parallel.

---

### P1 SEVERE DEBT: CRYPTOGRAPHIC PIPELINE & ALU SATURATION

#### [DEBT-P1-01] Sequential Cryptographic ALU Bubbles (Faux-Vectorization)

**Location:** Node & Hub `cryptography/aead.rs` (`encrypt_batch_ptrs`, `decrypt_batch_ptrs`)
**The Defect:** You pre-fetch 4 pointers into the L1d cache, but subsequently loop `for j in 0..4` calling `decrypt_one()`, which sequentially delegates to the `ring` crate (`LessSafeKey::open_in_place_separate_tag`).
**The Micro-Architecture Reality:**
Prefetching data into cache hides RAM latency, but your ALU execution remains strictly sequential.

* ARMv8 Cryptographic Extensions (`AESE`, `AESMC`) possess a hardware execution latency of  clock cycles, but a reciprocal throughput of  cycle.
* By evaluating block  entirely before beginning block , the CPU instruction pipeline sits completely starved (a "bubble") for 3 cycles waiting for the AES round dependency to resolve. You are achieving exactly **25% to 33%** of theoretical silicon throughput.
**The Mandate (Sprint 7):** Discard the `ring` crate for hot-path batch processing. You must implement or link interleaved SIMD assembly/intrinsics (`VAESE.8`, `VAESMC.8`). You must load the state vectors of 4 *independent* packets into the NEON 128-bit registers simultaneously (`v0-v3`, `v4-v7`) and interleave their AES round instructions. This perfectly masks the instruction latency and guarantees 100% ALU saturation.

#### [DEBT-P1-02] IP Fragmentation over RF (The Missing USO)

**Location:** Node `main.rs` (`tun_file.read(&mut frame[62..1562])`)
**The Defect:** The Node reads up to 1500 bytes from the TUN device, prepends a 62-byte M13 encapsulation header, and transmits a 1562-byte frame to the socket.
**The RF Physics Reality:** Standard WiFi 7 interfaces enforce a 1500 MTU. Sending 1562 bytes forces the Linux kernel to execute software IP fragmentation into two fragments (1500 bytes and 62 bytes).

* If an IP packet is fragmented into  fragments over a contested RF link with a packet loss probability of , the probability of losing the entire IP packet scales geometrically: .
* If the 62-byte fragment drops, the receiver's kernel discards the entire 1562-byte frame after a 30-second timeout. This geometric amplification of packet loss destroys the link.
**The Mandate (Sprint 4):** Implement Userspace Segmentation Offload (USO). The TUN interface MTU must be set to `65535` (Generic Receive Offload - GRO). The datapath intercepts 64KB TCP super-frames, encrypts them in bulk, and manually slices them into mathematically perfect, MTU-compliant 1380-byte RF fragments in userspace.

#### [DEBT-P1-03] Asymmetric CPU DoS via Unfiltered Replays (Missing  GHASH Shield)

**Location:** Node & Hub `cryptography/aead.rs` (`decrypt_one`)
**The Defect:** The code extracts `seq_id` to construct the nonce, but blindly delegates to AEAD decryption before validating the sequence number against an anti-replay window.
**The CS/Physics Reality:** AES-GCM tag verification requires Galois Hash (GHASH) carry-less multiplications (`PMULL`). If an adversary captures a legitimate frame and replays it 1,000,000 times at line-rate, the datapath will execute 1,000,000 GHASH authentications before discarding them due to tag/nonce rejection. This burns billions of cycles, starving legitimate telemetry of CPU time.
**The Mandate (Sprint 5):** Implement the RFC 6479 Anti-Replay bitmask. The `seq_id` must be evaluated against an  sliding bitmask using hardware intrinsics (shift + bitwise OR). Replays must be mathematically rejected in ** clock cycles** before a single cryptographic instruction is issued.

---

### P2 DEBT: CACHE DESTRUCTION & THREAD SAFETY

#### [DEBT-P2-01] Instruction Cache (L1i) Annihilation via Subprocess Spawning

**Location:** Node `network/datapath.rs` (`create_tun`, `setup_tunnel_routes`)
**The Defect:** Utilizing `std::process::Command::new` translates to `fork()` and `execve()`.
**The CS/Physics Reality:** `fork()` forces TLB shootdowns and page table clones. `execve()` invokes the ELF loader, flushing the L1i cache to load shell binaries (`ip`, `sysctl`, `tc`). This consumes ** to **. If the drone reconverges routing during an RF link flap, the  transport deadline is obliterated.
**The Mandate (Sprint 2):** Shell subprocesses are explicitly banned. Serialize binary C-structs (`rtmsg`, `ifinfomsg`) directly to the kernel via `AF_NETLINK` / `NETLINK_ROUTE` natively in memory.

#### [DEBT-P2-02] L1d Cache Thrashing via Colossal Stack Arrays

**Location:** Node `main.rs` (`rx_bufs: [[u8; 2048]; 64]`, `tx_bufs: [[u8; 1600]; 64]`)
**The Defect:** Instantiating  and  multidimensional buffers on the execution stack.
**The CS/Physics Reality:** The Cortex-A53 possesses a ** L1d cache**. By iterating across  of stack memory, you mathematically guarantee a 100% cache miss rate. Fetching from DDR4 costs  cycles per access, starving the vector processing pipeline.
**The Mandate (Sprint 1):** Packet buffers must never live on the stack. Map them directly into the NUMA-aligned HugePage Arena and reference them strictly via zero-copy `UmemSlice` constructs.

#### [DEBT-P2-03] Branch Predictor Collapse via Runtime FSM Enum Bloat

**Location:** Node `engine/runtime.rs` (`NodeState` enum), `main.rs` `process_rx_frame`
**The Defect:** Rust enums are sized to their largest variant. `NodeState` contains multiple `Vec<u8>` arrays (PQC keys), inflating the struct to hundreds of bytes.
**The CS/Physics Reality:** In the `process_rx_frame` hot-loop, checking `matches!(state, NodeState::Established)` forces the CPU to load this massive struct into L1d cache, evicting network payloads. The conditional branching forces the Cortex-A53 Branch History Table (BHT) to evaluate state per packet. Under stochastic RF packet loss, mispredictions are guaranteed, flushing the instruction pipeline for a 15-cycle penalty per miss.
**The Mandate (Sprint 3):** Implement Compile-Time Typestate Zero-Sized Types (ZSTs). The Hot Loop must only possess memory pointers for the `Established` state. Cryptographic state must be segregated to a slow-path arena.

#### [DEBT-P2-04] Unrecoverable Deadlock in Asynchronous Signal Handlers

**Location:** Node `main.rs` (`HUB_IP_GLOBAL.lock()` inside `nuke_cleanup_node`)
**The Defect:** `nuke_cleanup_node` is invoked by `std::panic::set_hook` and standard execution.
**The Logic Reality:** `std::sync::Mutex` utilizes `futex` and is **not async-signal-safe or panic-safe**. If the panic hook executes while the datapath holds the `Mutex` lock, the process will deadlock indefinitely. The drone becomes an unrecoverable zombie instead of restarting.
**The Mandate (Sprint 2):** `Mutex` is explicitly banned. Configuration data must be stored in a `std::sync::OnceLock` or an `AtomicPtr`. Lock-free, wait-free structures are the only acceptable mechanism for signal-safe teardown routines.

---

# M13: SYSTEMS ENGINEERING & OPERATIONAL MANDATES

This document serves as the absolute source of truth for the M13 Sovereign Transport Engine's memory safety, observability matrices, environment configurations, and Verification & Validation (V&V) protocols.

All architectural decisions herein are mandated by the physical realities of kernel memory models, RF propagation physics, and silicon micro-architecture. Deviations from these directives are strictly prohibited.

## I. MEMORY SAFETY & ABI INVARIANTS

### 1. Zero-Cost Memory Safety (`UmemSlice` Abstraction)

**The Threat:** The AF_XDP datapath relies on raw pointer arithmetic: `unsafe { frame_ptr.add(offset) }`. A single off-by-one error during packet encapsulation yields arbitrary memory overwrites, kernel panics, and exploitable CVEs.
**The Mandate:** During **Sprint 2**, all raw UMEM pointer accesses must be structurally eradicated.

* Implement a zero-cost `UmemSlice` struct that wraps `(*mut u8, usize)`. Construction incurs exactly one `unsafe` bounds check validating against the HugePage Arena boundaries.
* All subsequent byte extractions (`.frame() -> &mut [u8]`) must be mathematically guaranteed by the Rust compiler's spatial memory safety.

### 2. ABI Forward Allocations (Dead Parameters)

Function signatures across the M13 engine contain parameters prefixed with `_`. These are not dead code; they are strict Application Binary Interface (ABI) allocations for ensuing sprints. They ensure register allocation and struct padding remain consistent during early compilation.

| Parameter | Function Entity | Sprint Target | Architectural Purpose |
| --- | --- | --- | --- |
| `_offset` | `AssemblyBuffer::insert` | **Sprint 13** | Byte-offset tracking required for non-linear RLNC fragment reassembly. |
| `_now_ns` | `PeerTable::gc` | **Sprint 9** | Time-deterministic epoch eviction for Zombied peers via Bloom filters. |
| `_now_ns` | `JitterBuffer::drain` | **Sprint 12** | Isochronous playout calculation using absolute HW timestamps. |
| `_rtt_est` | `ReceiverState::needs_feedback` | **Sprint 11** | BBRv3 RTT-adaptive ACK pacing to prevent feedback channel saturation. |
| `_jbuf_depth` | `produce_feedback_frame` | **Sprint 12** | Encoding instantaneous jitter depth for upstream sender pacing. |
| `_jbuf_capacity` | `produce_feedback_frame` | **Sprint 12** | Upstream bufferbloat prevention signaling. |

*Directive: Upon Sprint execution, the `_` prefix shall be removed. The ABI signature remains frozen.*

### 3. Kernel Resource Anchors (RAII)

Fields marked `#[allow(dead_code)]` (`_umem_handle`, `sock_handle`, `obj`) govern the lifecycle of kernel-space file descriptors.
**Invariant:** Dropping or refactoring these fields will trigger automatic teardown of the UMEM allocations or eBPF programs via `Drop` traits. They must remain pinned to the `Engine` and `BpfSteersman` struct lifetimes.

---

## II. OPERATIONAL DETERMINISM (CONFIGURATION & LOGGING)

### 1. I/O Latency Eradication (Static Print Gating)

**The Threat:** Executing `eprintln!` inside the VPP loop invokes `writev` syscalls. This triggers context switches, flushes the L1i cache, and destroys the 50µs execution deadline.
**The Mandate:** During **Sprint 2**, all diagnostic logging inside `execute_graph` and its sub-nodes must be strictly gated by `#[cfg(debug_assertions)]` or a dedicated `debug-datapath` feature flag. The release binary must generate **zero** syscalls outside of network I/O.

### 2. Dynamic Environment Directives vs. Compile-Time Invariants

Hardcoded network values prohibit horizontal scaling and invalidate Namespace (NetNS) integration testing. However, memory layout constants must remain statically compiled to allow the LLVM optimizer to perform aggressive loop unrolling.

**A. Dynamic Configuration Targets (Sprint 2):**
These variables must be stripped from the `.text` segment and loaded into a statically initialized `OnceLock<M13Config>` from CLI arguments or Environment Variables at boot.

* **Tunnel Subnets:** `--tunnel-ip` (Replaces hardcoded `10.13.0.1/24`). Essential for overlapping swarm deployments.
* **TUN Properties:** `--tun-name` and `--mtu` (Replaces `m13tun0` and `1400`).
* **VPN Split Routes:** `--split-tunnel` (Boolean flag to disable the hardcoded `0.0.0.0/1` lockdown paradigm).
* **Socket Buffer Geometry:** `--sock-buf` (Replaces hardcoded `4MB`/`8MB`).
* **Hardware Fallbacks:** `--iface` and `--fallback-mac`.
* **Sysctl Blocks:** Tuning must be dynamically applied based on OS capability check.
* **Worker Thread Stack:** `--stack-size` (Replaces hardcoded `2MB`).

**B. Compile-Time Engine Constants (Strictly Immutable):**
These constants dictate physical cache alignment, mathematical boundaries, and prevent modulo division (`%`) latency. They must never be made dynamic.

* `MAX_WORKERS` (4), `MAX_PEERS` (256), `UMEM_SIZE` (1 GB), `FRAME_SIZE` (4096), `SLAB_DEPTH` (8192), `GRAPH_BATCH` (256), `VECTOR_SIZE` (64), `TX_RING_SIZE` (256), `JBUF_CAPACITY` (256).
* `REKEY_FRAME_LIMIT` (), `DEADLINE_NS` (50 µs), `REKEY_TIME_LIMIT_NS`, `HANDSHAKE_TIMEOUT_NS`, `FEEDBACK_RTT_DEFAULT_NS`, `HEXDUMP_INTERVAL_NS`.

---

## III. TELEMETRY & OBSERVABILITY MATRIX

### 1. Hub Observability

The Hub employs a dual-layer telemetry architecture: a `/dev/shm` shared-memory export for cross-process monitoring, and `eprintln!` diagnostic lines for operator visibility.

**Layer 1 — Shared Memory Export (`/dev/shm`)**

The `Telemetry` struct (`hub/src/engine/runtime.rs:453-481`) is `mmap()`'d to `/dev/shm`. Each field is `CachePadded<AtomicU64>` (128-byte aligned) to eliminate false sharing. The Monitor process (`--monitor` mode) reads these atomics with zero datapath contention.

Data flow: VPP graph nodes → `CycleStats` (per-batch, `hub/src/network/mod.rs:210-232`, 17 fields) → accumulated per subvector (`execute_subvector`, `main.rs:380-640`) → bridged to SHM via `fetch_add(Relaxed)` (`main.rs:1222-1232`).

| Field | Status | Location | Description |
| --- | --- | --- | --- |
| `pid` | **WIRED** | `main.rs:951` | Worker TID via `SYS_gettid` |
| `rx_count` | **WIRED** | `xdp.rs:321`, `main.rs:1225` | AF_XDP RX + VPP `parsed` accumulation |
| `tx_count` | **WIRED** | `xdp.rs:321` | AF_XDP TX completion ring |
| `drops` | **WIRED** | `main.rs:1224` | Parse failures + AEAD failures + classify drops |
| `cycles` | **WIRED** | `main.rs:1079` | Main loop iteration counter |
| `decrypt_ok` | **WIRED** | `main.rs:1222` | `aead_decrypt_vector()` success count |
| `auth_fail` | **WIRED** | `main.rs:1223` | AEAD MAC verification failures |
| `handshake_ok` | **WIRED** | `main.rs:632` | `process_finished_hub()` success |
| `handshake_fail` | **WIRED** | `main.rs:618,636` | PQC verification failure / malformed |
| `direction_fail` | **WIRED** | `datapath.rs:230` | Direction binding rejection (reflection defense) |
| `jbuf_depth_us` | **WIRED** | `main.rs:1154` | JitterBuffer instantaneous depth (µs) |
| `jbuf_jitter_us` | **WIRED** | `main.rs:1155` | RFC 3550 EWMA jitter estimate (µs) |
| `jbuf_releases` | **WIRED** | `main.rs:1156` | JitterBuffer cumulative releases |
| `jbuf_drops` | **WIRED** | `main.rs:1157` | JitterBuffer late/overflow drops |
| `parse_tsc_total` | **WIRED** | `main.rs:1228` | `rdtsc` delta: `rx_parse_raw()` |
| `decrypt_tsc_total` | **WIRED** | `main.rs:1229` | `rdtsc` delta: `aead_decrypt_vector()` |
| `classify_tsc_total` | **WIRED** | `main.rs:1230` | `rdtsc` delta: `classify()` |
| `scatter_tsc_total` | **WIRED** | `main.rs:1231` | `rdtsc` delta: `scatter()` |
| `tun_write_tsc_total` | **WIRED** | `main.rs:1232` | `rdtsc` delta: `tun_write_vector()` |
| `replay_drops` | **UNWIRED** | — | **Sprint 5:** Increment on RFC 6479 bitmask rejection, before AEAD. |
| `bbr_phase` | **UNWIRED** | — | **Sprint 11:** BbrPhase as `u32` (0=Startup, 1=Drain, 2=ProbeBW, 3=ProbeRTT). |
| `bbr_calibrated` | **UNWIRED** | — | **Sprint 11:** Flip to `1` on BBRv3 `STARTUP` exit. |
| `bbr_btlbw_kbps` | **UNWIRED** | — | **Sprint 11:** 10-RTT max-filtered bottleneck bandwidth. |
| `bbr_rtprop_us` | **UNWIRED** | — | **Sprint 11:** 10-second min-filtered RTT. |

**Layer 2 — Operator Diagnostics (`eprintln!`)**

| Diagnostic | Location | Trigger | Output |
| --- | --- | --- | --- |
| 1/sec telemetry line | `main.rs:1150` | Timer | `[M13-W0] RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD:{}/{} HS:{}/{} Slab:{}/{} Peers:{}/{} Up:{}s` |
| Slab exhaustion (UDP frag) | `main.rs:587` | `slab.alloc()` returns `None` during ServerHello UDP fragmentation | `[M13-DIAG] SLAB EXHAUSTION: ...Slab: {}/{} free. Enqueued {}/{} fragments.` |
| Slab exhaustion (L2 frag) | `main.rs:608` | `slab.alloc()` returns `None` during ServerHello L2 fragmentation | Same format, L2 AF_XDP path |
| Shutdown summary | `main.rs:1389` | Process exit | `Slab: {}/{} free. UDP TX:{} RX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} Peers:{} Up:{}s` |
| Hexdump RX | `process_rx_frame()` | `M13_HEXDUMP=1` | Per-packet hex dump of inbound frames |
| Hexdump TX | — | — | **UNWIRED. Sprint 2:** Wire after `scheduler.enqueue_bulk()` for bidirectional inspection. |

**Blind Spots:**

| Gap | Mandate |
| --- | --- |
| SPSC ring occupancy | Ring fill-level invisible to Monitor. Wire `available()` to `Telemetry` SHM. |
| TUN HK thread | `tun_housekeeping_thread()` (`main.rs:759-933`) has zero counters. VFS I/O latency, `pending_return` queue depth, and DPDK cache hit rates are all invisible. |
| `tun_writes` semantic shift | Post-R-02A, counts SPSC push operations, not VFS `write()`. Actual VFS I/O in TUN HK thread is unmetered. |
| ~~Elapsed time at shutdown~~ | ~~Shutdown summary does not emit session duration.~~ **RESOLVED R-04:** `Up:Xs` counter added to Hub and Node telemetry (both periodic and shutdown lines). |
| No RTT / jitter / throughput | Hub has no network quality metrics. Measured externally via `ping`/`iperf3` through tunnel (see `OBSERVATIONS.md`). |

---

### 2. Node Observability

The Node uses 7 local `u64` counters printed to stderr every 1 second. No `/dev/shm` export, no cross-process monitoring.

| Counter | Location | Description |
| --- | --- | --- |
| `rx_count` | Pass 0: CQE drain | UDP recv CQEs processed |
| `tx_count` | TUN read / echo / keepalive / registration | Successful `sock.send()` calls |
| `aead_ok_count` | Pass 1: batch decrypt | `decrypt_batch_ptrs()` successes |
| `aead_fail_count` | `process_rx_frame()` | AEAD open failures |
| `tun_read_count` | Pass 0: `TAG_TUN_READ` | TUN read CQEs processed |
| `tun_write_count` | Pass 2: `RxAction::TunWrite` | TUN writes staged |
| `State` | 1/sec report | `Reg` / `HS` / `Est` / `Disc` from `NodeState` enum |

**Output format:**
```
[M13-N0] RX:983 TX:986 TUN_R:982 TUN_W:965 AEAD_OK:965 FAIL:0 State:Est
```

**Blind Spots:**

| Gap | Mandate |
| --- | --- |
| No SHM export | **Sprint 2:** Node must gain a `Telemetry` struct to `/dev/shm`, matching Hub's architecture. `eprintln!` fails the operational requirement of external monitoring without log scraping. |
| io_uring ring pressure | `UringReactor` does not expose SQ depth or CQ overflow. Wire to detect SQPOLL stalls. |
| Hexdump TX | Same as Hub — `dump_tx()` unwired. |
| Elapsed time at shutdown | Shutdown line does not emit `elapsed_ns` or `duration_s`. Must be captured externally. |
| No reconnection counter | `HS_OK` is only on Hub side. Node has no visible counter for re-handshakes. Must infer from state transitions in log. |
| No RTT / jitter / throughput | Node has no network quality instrumentation. Measured externally via `ping`/`iperf3` through tunnel (see `OBSERVATIONS.md`). |

> **Cross-reference:** Sprint-over-sprint quantified metrics tracked in [`OBSERVATIONS.md`](OBSERVATIONS.md).


## IV. VERIFICATION & VALIDATION (V&V) MATRIX

"Happy Path" testing is prohibited. The transport engine must mathematically prove its resilience against adversarial physics and cryptographic anomalies. The system will not enter Phase 1 Flight Trials until it demonstrably passes the Tier 2 through Tier 5 Validation Matrix (**Sprint 15**).

### Tier 1: Core Mathematical Integration (`tests/integration.rs`)

Validates foundational mathematics and deterministic memory boundaries in absolute isolation. **Currently 30 tests** covering VPP graph pipeline, AEAD seal/open, PQC handshake round-trip, wire format parity, fragment reassembly, and rekey threshold enforcement.

* **Crate:** `tests/` (workspace member `m13-tests`, depends on `m13-hub`)
* **Run:** `cargo test -p m13-tests` or `cargo test --workspace`

### Tier 2: Namespace Bounded Integration (NetNS E2E)

Validates the physical pipeline without cloud variability.

* **Vector:** Linux Network Namespaces (`ns_node`, `ns_hub`) connected via a virtual ethernet (`veth`) pair.
* **Criteria:** PQC handshake mathematically converges within . Base `iperf3` throughput . `SIGKILL` on Node triggers Hub `E_PEER_TIMEOUT` detection within .

### Tier 3: Cryptographic Fuzzing (`libfuzzer`)

Validates that the execution path cannot panic or access OOB memory.

* **Vector:** `cargo-fuzz` compiling against LLVM libFuzzer.
* **Criteria:** Inject mutating byte arrays into `rx_parse_raw()`, `Assembler::feed()`, and `open_frame()`. Must mathematically return `false` without triggering side-channel panics, OOMs, or segmentation faults.

### Tier 4: Micro-Architectural Regression Benchmarking (`criterion`)

Instruction-Per-Cycle (IPC) variance tracking.

* **Vector:** `cargo bench` isolated to CPU Core 0 via `taskset`.
* **Criteria:** `aead_decrypt_vector` and `classify_route` batches must not regress in CPU cycle cost by  across any commit. Any regression automatically fails the CI/CD pipeline.

### Tier 5: Kinetic Survival / Chaos Engineering

Validates the system against the Contested Spectrum Environment (CSE).

* **Vector:** `tc netem` applied to Tier 2 virtual interfaces simulating Gilbert-Elliott loss models.
* **Criteria:**
* Apply `loss 30%`. Verify RLNC/FEC recovers the stream without TCP `DUP-ACK` storms.
* Apply `delay 4s`. Verify PQC Handshake survives without timing out.
* Apply `delay 6s`. Verify deterministic `HANDSHAKE_TIMEOUT_NS` correctly resets the FSM.
* Inject 100,000 duplicated `seq_id` payloads. Verify `replay_drops` atomic counter increments perfectly with CPU utilization  delta.
