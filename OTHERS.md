# OTHERS

## V. Phase 0: Silicon Provisioning & Micro-Architecture Isolation

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

* **Vector:** 129 strict deterministic tests executed via `cargo test` (70 Hub unit, 30 integration via `tests/integration.rs`, 29 Node unit).
* **Criteria:** Verifies VPP pipeline scatter/gather logic, Galois Field matrix inversions, AES-256-GCM AEAD bit-exactness, wire format parity, PQC SPSC ring lifecycle, and Compile-Time Typestate transitions. Zero allocations permitted in the hot path during execution.

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

## IX. Systems Engineering & Operational Mandates

### 1. Zero-Cost Memory Safety (`UmemSlice` Abstraction)

**The Threat:** The AF_XDP datapath relies on raw pointer arithmetic: `unsafe { frame_ptr.add(offset) }`. A single off-by-one error during packet encapsulation yields arbitrary memory overwrites, kernel panics, and exploitable CVEs.
**The Mandate:** All raw UMEM pointer accesses must be structurally eradicated.

* Implement a zero-cost `UmemSlice` struct that wraps `(*mut u8, usize)`. Construction incurs exactly one `unsafe` bounds check validating against the HugePage Arena boundaries.
* All subsequent byte extractions (`.frame() -> &mut [u8]`) must be mathematically guaranteed by the Rust compiler's spatial memory safety.

### 2. ABI Forward Allocations (Dead Parameters)

Function signatures across the M13 engine contain parameters prefixed with `_`. These are not dead code; they are strict Application Binary Interface (ABI) allocations for ensuing rounds. They ensure register allocation and struct padding remain consistent during early compilation.

| Parameter | Function Entity | Target | Architectural Purpose |
| --- | --- | --- | --- |
| `_offset` | `AssemblyBuffer::insert` | Round 5 | Byte-offset tracking required for non-linear RLNC fragment reassembly. |
| `_now_ns` | `PeerTable::gc` | Round 4 | Time-deterministic epoch eviction for Zombied peers via Bloom filters. |
| `_now_ns` | `JitterBuffer::drain` | Round 5 | Isochronous playout calculation using absolute HW timestamps. |
| `_rtt_est` | `ReceiverState::needs_feedback` | Round 4 | BBRv3 RTT-adaptive ACK pacing to prevent feedback channel saturation. |
| `_jbuf_depth` | `produce_feedback_frame` | Round 5 | Encoding instantaneous jitter depth for upstream sender pacing. |
| `_jbuf_capacity` | `produce_feedback_frame` | Round 5 | Upstream bufferbloat prevention signaling. |

*Directive: Upon execution, the `_` prefix shall be removed. The ABI signature remains frozen.*

### 3. Kernel Resource Anchors (RAII)

Fields marked `#[allow(dead_code)]` (`_umem_handle`, `sock_handle`, `obj`) govern the lifecycle of kernel-space file descriptors.
**Invariant:** Dropping or refactoring these fields will trigger automatic teardown of the UMEM allocations or eBPF programs via `Drop` traits. They must remain pinned to the `Engine` and `BpfSteersman` struct lifetimes.

### 4. I/O Latency Eradication (Static Print Gating)

**The Threat:** Executing `eprintln!` inside the VPP loop invokes `writev` syscalls. This triggers context switches, flushes the L1i cache, and destroys the 50µs execution deadline.
**The Mandate:** All diagnostic logging inside `execute_graph` and its sub-nodes must be strictly gated by `#[cfg(debug_assertions)]` or a dedicated `debug-datapath` feature flag. The release binary must generate **zero** syscalls outside of network I/O.

### 5. Dynamic Environment Directives vs. Compile-Time Invariants

Hardcoded network values prohibit horizontal scaling and invalidate Namespace (NetNS) integration testing. However, memory layout constants must remain statically compiled to allow the LLVM optimizer to perform aggressive loop unrolling.

**A. Dynamic Configuration Targets:**
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
* `REKEY_FRAME_LIMIT` (), `DEADLINE_NS` (50 µs), `REKEY_TIME_LIMIT_NS`, `HANDSHAKE_RETX_INTERVAL_NS`, `FEEDBACK_RTT_DEFAULT_NS`, `HEXDUMP_INTERVAL_NS`.

### 6. Telemetry & Observability Matrix

#### Hub Observability

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
| `replay_drops` | **UNWIRED** | — | Increment on RFC 6479 bitmask rejection, before AEAD. |
| `bbr_phase` | **UNWIRED** | — | BbrPhase as `u32` (0=Startup, 1=Drain, 2=ProbeBW, 3=ProbeRTT). |
| `bbr_calibrated` | **UNWIRED** | — | Flip to `1` on BBRv3 `STARTUP` exit. |
| `bbr_btlbw_kbps` | **UNWIRED** | — | 10-RTT max-filtered bottleneck bandwidth. |
| `bbr_rtprop_us` | **UNWIRED** | — | 10-second min-filtered RTT. |

**Layer 2 — Operator Diagnostics (`eprintln!`)**

| Diagnostic | Location | Trigger | Output |
| --- | --- | --- | --- |
| 1/sec telemetry line | `main.rs:1150` | Timer | `[M13-W0] RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD:{}/{} HS:{}/{} Slab:{}/{} Peers:{}/{} Up:{}s` |
| Slab exhaustion (UDP frag) | `main.rs:587` | `slab.alloc()` returns `None` during ServerHello UDP fragmentation | `[M13-DIAG] SLAB EXHAUSTION: ...Slab: {}/{} free. Enqueued {}/{} fragments.` |
| Slab exhaustion (L2 frag) | `main.rs:608` | `slab.alloc()` returns `None` during ServerHello L2 fragmentation | Same format, L2 AF_XDP path |
| Shutdown summary | `main.rs:1389` | Process exit | `Slab: {}/{} free. UDP TX:{} RX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} Peers:{} Up:{}s` |
| Hexdump RX | `process_rx_frame()` | `M13_HEXDUMP=1` | Per-packet hex dump of inbound frames |
| Hexdump TX | — | — | **UNWIRED.** Wire after `scheduler.enqueue_bulk()` for bidirectional inspection. |

**Blind Spots:**

| Gap | Mandate |
| --- | --- |
| SPSC ring occupancy | Ring fill-level invisible to Monitor. Wire `available()` to `Telemetry` SHM. |
| TUN HK thread | `tun_housekeeping_thread()` (`main.rs:759-933`) has zero counters. VFS I/O latency, `pending_return` queue depth, and DPDK cache hit rates are all invisible. |
| `tun_writes` semantic shift | Post-R-02A, counts SPSC push operations, not VFS `write()`. Actual VFS I/O in TUN HK thread is unmetered. |

#### Node Observability

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
| No SHM export | Node must gain a `Telemetry` struct to `/dev/shm`, matching Hub's architecture. `eprintln!` fails the operational requirement of external monitoring without log scraping. |
| io_uring ring pressure | `UringReactor` does not expose SQ depth or CQ overflow. Wire to detect SQPOLL stalls. |
| Hexdump TX | Same as Hub — `dump_tx()` unwired. |
| Elapsed time at shutdown | Shutdown line does not emit `elapsed_ns` or `duration_s`. Must be captured externally. |
| No reconnection counter | `HS_OK` is only on Hub side. Node has no visible counter for re-handshakes. Must infer from state transitions in log. |

> **Cross-reference:** Round-over-round quantified metrics tracked in [`OBSERVATIONS.md`](OBSERVATIONS.md).

---

## X. Project Documents

| Document | Purpose |
|----------|---------|
| [TODO.md](TODO.md) | Technical debt ledger, sprint cards, telemetry matrix, V&V tiers |
| [OBSERVATIONS.md](OBSERVATIONS.md) | Quantified sprint metrics, cross-sprint comparison tables, measurement formulas |
| [PROTOCOL.md](PROTOCOL.md) | Engineering workflow: pre-sprint research, execution, debugging, post-sprint documentation |
