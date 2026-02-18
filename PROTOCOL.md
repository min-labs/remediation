# M13 Engineering Protocol

> **Purpose**: 
> Codify the exact process for executing sprints. 
> Every sprint follows these four phases in order. 
> Skipping phases or reordering them is prohibited.

---

## Phase 0: Environment Prerequisites

**Trigger**: Before any sprint begins. Verify once per machine, re-verify after kernel upgrades or hardware changes.

```bash
# ── Kernel ──
uname -r                               # Must be 6.12+ (io_uring PBR, XDP_REDIRECT)
cat /boot/config-$(uname -r) | grep IO_URING   # CONFIG_IO_URING=y

# ── HugePages ──
grep HugePages /proc/meminfo           # HugePages_Free ≥ 600
cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages  # ≥ 600

# ── NIC (Hub only) ──
ethtool -l <iface>                     # Combined queues = worker count
ethtool -L <iface> combined 1          # Force single queue for AF_XDP steering
ethtool -K <iface> rxvlan off          # Disable VLAN offload (XDP compat)

# ── Resource Limits ──
ulimit -l                              # Must be 'unlimited' for UMEM mmap
cat /proc/sys/net/core/optmem_max      # ≥ 2097152 for AF_XDP socket buffers

# ── io_uring (Node only) ──
cat /proc/sys/kernel/io_uring_group     # Must include current user's GID
ls /dev/io_uring 2>/dev/null || echo "io_uring dev not available (OK if kernel ≥ 6.12)"
```

> **If any check fails, fix it before starting the sprint.** Environment issues masquerade
> as code bugs and waste debugging cycles (see: AF_XDP zerocopy failure, R-01).

---

## Phase 1: Pre-Sprint — Research & Fact-Check

**Trigger**: Sprint scope defined (from `TODO.md` sprint card).

### 1.1 Sprint Intake

1. Read the sprint card in `TODO.md` under **M13 REMEDIATION ROADMAP (R-SERIES)** — scope, target defect, rationale, and implementation method for the next sprint in sequence.
2. Identify the core technical claims and constraints (e.g., "SPSC ring eliminates false sharing", "io_uring SQPOLL eliminates context switches").
3. List every assumption that the sprint depends on.

### 1.2 Literature Search

For each assumption or technique in the sprint, search:

| Source | What to Look For |
|--------|-----------------|
| **RFCs / Standards** | Canonical specification (e.g., RFC 6479 for anti-replay, FIPS 203/204 for ML-KEM/ML-DSA) |
| **Kernel Docs** | `Documentation/networking/af_xdp.rst`, `io_uring.rst`, relevant `man` pages |
| **Vendor References** | Intel/ARM optimization manuals, NIC datasheets, DPDK guides |
| **Academic Papers** | Peer-reviewed publications for algorithms (HKDF, RLNC, BBR) |
| **Industry Practice** | How do HFT, WireGuard, Cloudflare, Google, Hyperscaler, Starlink, Youtube, Instagram, Tiktok, Facebook, Netflix, Lockheed Martin handle the same problem? (Must search for all of them, not just one.) |
| **Crate Documentation** | `docs.rs` for any new dependency — verify API correctness, not just examples |

### 1.3 Context-Appropriate Adjustment

Not every industry practice applies to M13. Filter through:

- **Deployment context**: Single-Node satellite uplink, not datacenter. Latency > 20ms, loss > 1%.
- **Threat model**: Post-quantum adversary, contested spectrum. Not just TLS web traffic.
- **Hardware constraints**: ARM Cortex-A53 (2-wide in-order, Kria K26 SOM), not Xeon. NEON, not AVX-512.
- **Scale**: 1–16 peers, not 100K. Optimize for per-packet latency, not connection count.

### 1.4 Mutual Agreement Gate

```
Loop:
  1. Present findings: what the literature says, how it applies (or doesn't) to M13.
  2. User reviews, challenges assumptions, asks questions.
  3. Revise based on feedback.
  4. Repeat until both sides agree on the approach.
  
Exit condition: Explicit user approval to proceed to Phase 2.
No code is written until Phase 1 completes.
```

---

## Phase 2: Execution — Apply Changes & Test

**Trigger**: Phase 1 approval received.

### 2.1 Implementation Order

1. **Dependencies first**: New crates, new modules, new types.
2. **Core logic**: The actual algorithm / data structure / protocol change.
3. **Integration**: Wire into existing call sites, update state machines.
4. **Tests**: Unit tests for new code, integration tests for changed paths.

### 2.2 Integration Audit (EXTREMELY IMPORTANT: DO NOT SKIP)

**Before deployment, prove that every change is wired and alive — not orphan code.**

> **TIMEOUT RULE:** Every CLI command in this section has a **60-second hard ceiling**. If any
> command hangs beyond 30 seconds, **immediately halt the operation**, report which steps
> passed / failed so far, and provide the user with the remaining commands to run manually.
> Do not wait indefinitely — CLI hangs are a known failure mode.

#### Static Liveness Proof (Zero-Waste Determinism)

Lexical analysis (`grep`/Bash) is explicitly banned due to macro-expansion blindness. M13 achieves proof of liveness via strict compiler lints and deterministic build-time verification that traverse the intermediate compiler graphs.

**Step 1 — MIR Call-Graph Reachability:**

The compiler models function execution as a directed graph G = (V, E). A function v is live if and only if a path exists from a root entry point (e.g., `main`, eBPF hooks) to v in the MIR transitive closure. Any unreachable function aborts the build.

```bash
# Enforce via strict compiler lints — zero dead code tolerance:
RUSTFLAGS="-D dead_code -D unused" cargo build --release 2>&1 | tail -20
```

**Step 2 — HIR Field-Level Memory Validation:**

For every field f within a struct S, the compiler verifies both a write state (∃ assignment to S.f) and a read state (∃ subsequent load from S.f). Fields that are written but never read, or read but never modified, are phantom payloads — compilation panics.

```bash
# Compiler lint catches unused struct fields:
RUSTFLAGS="-D dead_code -D unused_variables" cargo build --release 2>&1 | tail -20
```

**Step 3 — MIR Semantic Liveness (Def-Use Chains):**

Strict dataflow analysis on the MIR control-flow graph. A variable definition is only valid if it reaches a consumer that influences hardware state (io_uring submission, AF_XDP ring update, DMA write). Dead stores and discarded error codes abort the build.

```bash
# Enforce no dead stores, no discarded Results:
RUSTFLAGS="-D unused_must_use -D unused_assignments" cargo build --release 2>&1 | tail -20
```

**Step 4 — Zero-Tolerance Dependency Pruning:**

If a crate is declared in `Cargo.toml` but lacks a resolved invocation edge in the lowered AST, the build fails. Zero waivers for unused dependencies.

```bash
# Verify zero phantom crate dependencies:
cargo +nightly udeps --workspace 2>&1
```

**Step 5 — Full Test Suite:**

```bash
# Full workspace tests — includes tests/integration.rs (integration suite):
cargo test --workspace 2>&1 | tail -20        # 100% pass rate required
```

`tests/integration.rs` is the primary integration gate — it exercises scatter/classify, AEAD seal/open, fragment reassembly (`Assembler::feed`), wire format parity, and handshake state transitions. If `integration.rs` passes, the VPP graph nodes are proven to interoperate. If it fails, the sprint halts.

**Step 6 — Double-Audit (Brute-Force Integration Trace):**

Compiler lints prove syntactic liveness but cannot detect semantic drift — a function can compile cleanly yet be orphaned from the actual runtime pipeline because its caller was refactored, its return value is silently discarded, or its call site was guarded behind a `false` branch. This step opens every source file, reads every function body, and proves the **actual logic** is called, receives correct inputs, and feeds its output into the next pipeline stage.

**6a — Hub Execution Pipeline (README §3.2, §4 Phase 1):**

Open `hub/src/main.rs` and trace the following call chain. For each arrow (→), open the callee's source file and verify the function body exists, the parameters match what the caller passes, and the return value is consumed:

```
main()                                                           [hub/src/main.rs:44]
  → Signal handlers: SIGTERM/SIGINT → AtomicBool SHUTDOWN        [main.rs:48-51]
  → Panic hook: nuke_cleanup_hub() on unwind                     [main.rs:55-59]
  → CLI parse:                                                   [main.rs:65-103]
      if_name, tunnel_mode, single_queue, listen_port, hexdump_mode
      --monitor → run_monitor() → read /dev/shm telemetry (exits early)
  → Set M13_LISTEN_PORT env var (default 443)                    [main.rs:109-123]
  → run_executive(if_name, single_queue, tunnel)                 [main.rs:124]

run_executive()                                                  [hub/src/main.rs:128]
  → Pre-flight cleanup:                                          [main.rs:141-185]
      Kill stale m13-hub: pgrep + SIGKILL (exclude self)
      Detach stale XDP: ip link set <if> xdp off / xdpgeneric off
      ethtool -L <if> combined 1 — collapse NIC to single queue
        (AF_XDP binds queue 0; RSS would distribute packets away)
      Hugepage allocation: ceil(UMEM_SIZE / 2MB) → /proc/sys/vm/nr_hugepages
  → calibrate_tsc() — open runtime.rs, verify TSC calibration    [hub/engine/runtime.rs]
  → lock_pmu() + fence_interrupts()                              [hub/engine/runtime.rs]
      perf_event_open on every core (prevent frequency scaling)
      IRQ affinity: move all IRQs off isolated cores
  → discover_isolated_cores()                                    [hub/engine/runtime.rs]
      Parse /sys/devices/system/cpu/isolated or M13_MOCK_CMDLINE
  → BpfSteersman::load_and_attach(if_name) — open bpf.rs:       [hub/network/bpf.rs]
      Read BPF_OBJECT_PATH (set by build.rs)
      bpf_object__open_file() → bpf_object__load()
      XDP program m13_steersman:                                 [hub/build.rs:44-77]
        Path 1: EtherType 0x88B5 → bpf_redirect_map(xsks_map)   [raw L2 M13]
        Path 2: IPv4 UDP dst port 443 → bpf_redirect_map         [UDP-encaps M13]
        Default: XDP_PASS (SSH, ARP, etc. → kernel stack)
      bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE)
        Fallback: XDP_FLAGS_SKB_MODE if driver mode fails
      Returns xsks_map fd for AF_XDP socket registration
  → create_tun("m13tun0") — open datapath.rs:                   [hub/network/datapath.rs]
      ioctl(TUNSETIFF, IFF_TUN | IFF_NO_PI) → TUN fd
  → setup_nat() — verify called immediately after create_tun:   [hub/network/datapath.rs]
      ip link set m13tun0 up
      ip addr add 10.13.0.1/24 dev m13tun0
      sysctl net.ipv4.ip_forward = 1
      iptables -t nat -A POSTROUTING -s 10.13.0.0/24 -j MASQUERADE
      iptables -A FORWARD -i m13tun0 -j ACCEPT
      iptables -A FORWARD -o m13tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
      sysctl rmem_max/wmem_max/netdev_max_backlog/rmem_default/wmem_default
  → SpscRing::new() ×4 — open spsc.rs, verify:                  [hub/engine/spsc.rs]
      tx_tun:      Producer<PacketDesc> → Consumer<PacketDesc>    (datapath → TUN HK)
      rx_tun:      Producer<PacketDesc> → Consumer<PacketDesc>    (TUN HK → datapath)
      free_to_tun: Producer<u32> → Consumer<u32>                  (datapath → TUN HK slab IDs)
      free_to_dp:  Producer<u32> → Consumer<u32>                  (TUN HK → datapath slab IDs)
      All rings: lock-free, cache-aligned, depth 2048, power-of-two
  → OnceLock<(usize, u32)> for UMEM base sharing                [main.rs:232-233]
      Worker 0 publishes (umem_base_ptr, frame_size) after Engine::new()
      TUN HK thread blocks on .get() until published
  → thread::Builder::new().spawn(tun_housekeeping_thread):      [main.rs:236-254]
      Pinned to last isolated core
      tun_housekeeping_thread():                                 [main.rs:757-940]
        Blocks on OnceLock until UMEM base published by Worker 0
        DPDK-style local cache: [u32; 4096] pending_return
        Main loop:
          Phase 0: Drain pending_return → free_slab_tx.push_batch()
          Phase 1 (TX to kernel): Pop PacketDesc from rx_from_dp →
            write(tun_fd, payload) → return slab ID to free_slab_tx
          Phase 2 (RX from kernel): poll(POLLIN, 1ms) →
            alloc from free_slab_rx → read(tun_fd) →
            build ETH+M13 header in UMEM → push PacketDesc to tx_to_dp
  → Worker 0 handle distribution via .take()                     [main.rs:262-278]
      Only worker 0 gets SPSC Producer/Consumer handles
  → worker_entry(core_id, ...) — verify:                         [main.rs:942-1542]
      pin_to_core(core_id) + verify_affinity()                   [hub/engine/runtime.rs]
      Telemetry::map_worker() → /dev/shm mmap                   [hub/engine/runtime.rs]
      Engine::new_zerocopy(if_name, queue_id, bpf_map_fd):      [hub/network/xdp.rs]
        HugeTLB mmap for UMEM (2MB hugepages)
        xsk_socket__create_shared() → AF_XDP socket
        bpf_map_update_elem(xsks_map, queue_id, xsk_fd)
        Fill Ring, Completion Ring, RX Ring, TX Ring initialized
      Worker 0: umem_info.set() → unblock TUN HK thread          [main.rs:962-966]
      FixedSlab::new(8192)                                        [hub/engine/runtime.rs]
        Bitmap-based O(1) allocator for UMEM frame indices
      Scheduler::new() — dual-queue (critical/bulk) + EDT        [hub/engine/protocol.rs]
      PeerTable::new(epoch_ns) — 256 slots + assemblers          [hub/engine/protocol.rs]
        Each slot: PeerSlot(64B align), Scheduler, ReceiverState, JitterBuffer,
        Assembler(8 HugeTLB AssemblySlots), cipher, hs_sidecar
      Detect hub_ip: get_interface_ip() + resolve_gateway_mac()  [hub/network/datapath.rs]
      Pre-stamp ALL 8192 slab frames with ETH+M13 headers:       [main.rs:1007-1022]
        dst=[0xFF;6], src=iface_mac, ethertype=0x88B5(BE),
        magic=0xD1, version=0x01, seq=0, flags=0
      measure_epsilon_proc() → processing jitter floor            [hub/engine/protocol.rs]
      JitterBuffer::new()                                        [hub/engine/protocol.rs]
        RFC 3550 EWMA Q60.4 fixed-point jitter estimator
      PQC Arena Allocation:                                      [main.rs:1052-1064]
        payload_arena: [[0u8; 9216]; MAX_PEERS] → leaked *mut
          (datapath writes reassembled handshake, Core 0 reads)
        hs_state_arena: [FlatHubHandshakeState; MAX_PEERS] → leaked *mut
          (Core 0 local: stores inter-message handshake state)
      make_pqc_spsc() ×2:                                        [hub/cryptography/async_pqc.rs]
        pqc_req: Producer<PqcReq> → Consumer<PqcReq>              (datapath → Core 0)
        pqc_resp: Producer<PqcResp> → Consumer<PqcResp>           (Core 0 → datapath)
      thread::Builder::new().spawn(pqc_worker_thread):           [main.rs:1070-1081]
        Arena pointers passed as usize (Send-safe), reconstructed inside closure
        pqc_worker_thread() receives: core_id, pqc_req_cons, pqc_resp_prod, arenas, MAX_PEERS
        Main loop: pop PqcReq batch → dispatch by msg_type:
          msg_type=0x01: process_client_hello_hub() → store FlatHubHandshakeState → push PqcResp
          msg_type=0x03: process_finished_hub() → derive session_key → push PqcResp
      EdtPacer::new(cal, 100_000_000)                             [hub/network/uso_pacer.rs]
        Zero-spin EDT pacer, 100 Mbps default MANET link rate

      VPP Main Loop — verify each graph node is actually invoked per iteration:
        [SHUTDOWN check]:                                        [main.rs:1097-1131]
          3× FIN burst to all Established peers via
          send_fin_burst_udp() or send_fin_burst_l2()
          Then RX-only until FIN-ACK or deadline
        engine.recycle_tx() + engine.refill_rx()                 [hub/network/xdp.rs]
        execute_tx_graph() (worker 0 only):                      [main.rs:651-755]
          free_to_dp_cons.pop_batch() → slab.free()
          Demand-driven slab provision: free_to_tun_prod.push_batch()
          Pop TUN frames: rx_tun_cons.pop_batch() →
            lookup_by_tunnel_ip() → seal_frame() → build_fragmented_raw_udp_rlnc()
            EDT pacer.pace() → enqueue_bulk_edt() with release_ns timestamp
        Telemetry: 1/sec report                                  [main.rs:1180-1196]
        STAGE 0: Adaptive batch drain                            [main.rs:1198-1207]
          engine.poll_rx_batch() → xdp_desc[] (up to GRAPH_BATCH=256)
          Coalesce loop: gather until 256 or DEADLINE_NS (50µs)
        STAGE 0.5: Jitter buffer drain                           [main.rs:1209-1222]
          jbuf.drain(now_ns, scheduler) → release buffered frames
        execute_graph(rx_descs, GraphCtx):                       [main.rs:340-379]
          execute_subvector() per 64-packet chunk:               [main.rs:381-552]
            rx_parse_raw() → PacketVector                        [hub/network/datapath.rs]
              Validates magic=0xD1, version=0x01, crypto_ver routing:
              crypto_ver=0x00 → cleartext_out (handshake/control)
              crypto_ver=0x01 → decrypt_out (AEAD encrypted)
              Extracts src_ip/src_port from IP/UDP header offsets
              Calls peers.lookup_or_insert() — verify PeerTable method
              Learns hub_ip/gateway_mac from first inbound
            aead_decrypt_vector()                                [hub/network/datapath.rs]
              Per-packet: peer lookup → open_frame() with peer cipher
              Nonce read from frame[sig+20..sig+32] (12 bytes)
              Reflection guard: nonce_bytes[8] ≠ DIR_HUB_TO_NODE (0x00)
            classify_route() → Disposition                       [hub/network/datapath.rs]
              Priority routing (first match wins):
                FLAG_FIN       → Consumed (FIN deferred to post-executor)
                FLAG_FEEDBACK  → Feedback
                FLAG_FRAGMENT  → Handshake
                FLAG_HANDSHAKE → Handshake
                FLAG_CONTROL   → Consumed (echo, keepalive)
                FLAG_TUNNEL    → TunWrite
                FLAG_FEC       → RlncDecode
                default        → TxEnqueue (data forward)
            scatter()                                            [hub/network/mod.rs]
              4-wide prefetch scatter into per-NextNode output vectors
            tun_write_vector()                                   [hub/network/datapath.rs]
              Push PacketDesc to SPSC tx_tun ring → TUN HK thread
              (worker 0 only; other workers: direct write(tun_fd))
            CycleStats accumulation → Telemetry SHM
        process_fragment() — handshake fragments:                [main.rs:554-649]
          typestate::validate_frag_index(index, total)           [hub/engine/typestate.rs]
            Branchless: (index >= total) as usize → panic-free clamp
          typestate::validate_frag_data_bounds(offset, len)     [hub/engine/typestate.rs]
            Branchless OOB check preventing adversarial slice
          peers.assemblers[pidx].feed(msg_id, index, total, offset, data)
          On reassembly complete:
            process_handshake_message() dispatches by reassembled[0]:
              HS_CLIENT_HELLO (0x01): copy 4194B to payload_arena[pidx] → push PqcReq
              HS_FINISHED (0x03): copy 4628B to payload_arena[pidx] → push PqcReq
              Zero inline lattice math — all PQC crypto offloaded to Core 0
        FIN processing (deferred from executor):                 [main.rs:1309-1338]
          FIN received → send_fin_burst_*() FIN-ACK → evict peer
          FIN-ACK received → clear deadline, close complete
        Registration echo processing:                            [main.rs:1340-1417]
          For each non-Established peer:
          100ms throttle → build Echo (FLAG_CONTROL) →
          build_raw_udp_frame() or raw L2 → enqueue_critical()
          Slab leak prevention: free on enqueue failure
        STAGE 3: Feedback generation                             [main.rs:1422, 310-336]
          stage_feedback_gen() if needs_feedback(pkt_since_feedback ≥ 32)
          produce_feedback_frame() → 102B → enqueue_critical()
        V4: PQC Response Drain:                                  [main.rs:1424-1516]
          Pop PqcResp batch from pqc_resp_cons:
            msg_type=0x02 (ServerHello):
              Frame 8788B payload with local hub_ip/gateway_mac
              build_fragmented_raw_udp_rlnc() or build_fragmented_l2_rlnc()
              k = ceil(8788/1402) = 7 systematic, m=0 (FLAG_HANDSHAKE → no RLNC)
              → enqueue_critical() (handshake frames are priority)
            msg_type=0x03 (SessionEstablished):
              Install AES-256-GCM LessSafeKey in peers.ciphers[pidx]
              PeerLifecycle::Established, alloc_tunnel_ip() → 10.13.0.X
              Clear hs_sidecar
        seal_frame() — verify in hub/cryptography/aead.rs:
          Nonce construction: seq_id(8) || direction(1) || zeros(3) = 12 bytes
          Nonce stored at frame[sig+20..sig+32]
          Tag (16 bytes) stored at frame[sig+4..sig+20]
          AAD: frame[sig..sig+4] (magic, version, crypto_ver, reserved)
          Encrypted region: frame[sig+32..frame_end] (seq_id, flags, payload_len, padding, payload)
        STAGE 6: Schedule TX                                     [main.rs:1518-1523]
          scheduler.schedule(tx_path, now_ns):
          EDT-gated dequeue: critical-first, then bulk
          Won't release frames before release_ns timestamp
          tx_path.stage_tx_addr() → tx_path.commit_tx() → kick_tx()
        Periodic GC (every 10,000 cycles):                       [main.rs:1524-1529]
          peers.gc() + assembler.gc() per peer (5-second stale expiry)
```

**6b — Node Execution Pipeline (README §3.4, §4 Phase 2):**

Open `node/src/main.rs` and trace:

```
main()                                                           [node/src/main.rs:37]
  → Signal handlers: SIGTERM/SIGINT → AtomicBool SHUTDOWN        [main.rs:42-44]
  → Panic hook: nuke_cleanup_node()                               [main.rs:48-52]
      Calls: nuke_cleanup("m13tun0", hub_ip)                     [node/network/datapath.rs]
      Idempotent: ip route del, ip link del, iptables flush
  → CLI parse:                                                    [main.rs:54-74]
      echo, hexdump, tunnel, hub_ip (required)
  → create_tun("m13tun0") — open datapath.rs:                   [node/network/datapath.rs]
      ioctl(TUNSETIFF, IFF_TUN | IFF_NO_PI) → File
  → Store hub IP in HUB_IP_GLOBAL Mutex                          [main.rs:78-79]
      (for panic hook route teardown)
  → run_uring_worker(hub_addr, echo, hexdump, tun_file)          [main.rs:81]

run_uring_worker()                                                [node/src/main.rs:723]
  → calibrate_tsc() — open runtime.rs, verify TSC calibration    [node/engine/runtime.rs]
  → tune_system_buffers() — verify sysctl writes:                [main.rs:274-330]
      net.core.rmem_max, wmem_max, netdev_max_backlog,
      rmem_default, wmem_default (all to 4MB+)
  → UdpSocket::bind("0.0.0.0:0") → connect(hub_addr)
      O_NONBLOCK, SO_RCVBUFFORCE=8MB, SO_SNDBUFFORCE=8MB
  → UringReactor::new(raw_fd, cpu=0) — open uring_reactor.rs:   [node/network/uring_reactor.rs]
      HugeTLB mmap: 2MB-aligned arena (PBR metadata + data frames)
      IoUring::builder()
        .setup_sqpoll(2000ms)          SQPOLL kernel thread, 2s idle timeout
        .setup_single_issuer()         Single-thread SQ ownership
      SYS_io_uring_register IORING_REGISTER_PBUF_RING
        Register Provided Buffer Ring with kernel
      Pre-register all BIDs in PBR
      arm_multishot_recv()
        Single SQE IORING_OP_RECV with IOSQE_BUFFER_SELECT + MULTISHOT
        Survives for lifetime of socket (no per-packet SQE submission)
  → Arm TUN reads: BIDs in [UDP_RING_ENTRIES .. TOTAL_BIDS)
  → Assembler::init(alloc_asm_arena()) — open protocol.rs:      [node/engine/protocol.rs]
      8 AssemblySlots × 9280B per slot (HugeTLB arena)
  → Build M13 header template:                                   [node/engine/protocol.rs]
      detect_mac(None) → LAA random MAC
      src_mac, hub_mac=[0xFF;6], magic=0xD1, version=0x01
  → build_m13_frame(src_mac, hub_mac, seq=0, flags=0x00)         [node/engine/protocol.rs:61]
      → 62-byte registration frame: ETH(14) + M13(48), all zeroes payload
  → sock.send(&frame) — registration frame sent
  → NodeState::Registering                                        [node/engine/runtime.rs]

  CQE Three-Pass Main Loop — verify each pass is actually coded:

    SHUTDOWN check + 30s connection timeout

    Pass 0 (CQE Drain + Classify):
      reactor.ring.completion().sync() — verify CQE drain
      Drain up to 128 CQEs into cqe_batch[]
      For each CQE, classify by tag:
        TAG_UDP_RECV_MULTISHOT → collect into recv_bids[]/recv_lens[]
          Track multishot termination (IORING_CQE_F_MORE == 0 → rearm)
        TAG_TUN_READ → build M13 header in-place → seal_frame → stage_udp_send
        TAG_TUN_WRITE → recycle BID to PBR (add_buffer_to_pbr + commit_pbr)
        TAG_UDP_SEND_ECHO/TUN → arm_tun_read(bid) to recycle BID

    Pass 1 (Vectorized AEAD Batch Decrypt):
      Guard: Established AND recv_count > 0
      Scan recv frames for crypto_flag == 0x01 → collect enc_ptrs[]
      decrypt_batch_ptrs() — open aead.rs, verify:               [node/cryptography/aead.rs]
        4-at-a-time prefetch → saturate AES-NI/ARMv8-CE pipeline
        decrypt_one() per frame:
          Read nonce from frame[sig+20..sig+32] (12 bytes)
          Reflection guard: nonce_bytes[8] == our_dir → reject
          Read tag from frame[sig+4..sig+20] (16 bytes)
          AAD: frame[sig..sig+4] (4 bytes)
          open_in_place_separate_tag() → verify+decrypt
        Stamps PRE_DECRYPTED_MARKER (0x02) at frame[ETH_HDR_SIZE + 2] on success
      Rekey check: frame_count >= REKEY_FRAME_LIMIT (2³²)
        OR elapsed >= REKEY_TIME_LIMIT_NS (1 hour)

    Pass 2 (Per-Frame RxAction Dispatch):
      process_rx_frame() returns RxAction — verify enum variants:
        NeedHandshakeInit → initiate_handshake():                [node/cryptography/handshake.rs]
          OsRng → client_nonce (32 bytes)
          ML-KEM-1024 KeyGen → (dk_node, ek_node)                [ml-kem crate]
            ek_node = 1568 bytes (encapsulation key)
            dk_node = decapsulation key (stored in NodeHandshakeState)
          ML-DSA-87 KeyGen → (sk_node, pk_node)                  [ml-dsa crate]
            pk_node = 2592 bytes (verification key)
            sk_node = signing key (stored in NodeHandshakeState)
          Build ClientHello payload (4194B):
            [0] = HS_CLIENT_HELLO (0x01)
            [1] = version (0x01)
            [2..34] = client_nonce
            [34..1602] = ek_node (ML-KEM-1024 encapsulation key)
            [1602..4194] = pk_node (ML-DSA-87 verification key)
          send_fragmented_udp(payload, flags=FLAG_CONTROL|FLAG_HANDSHAKE)
            k = ceil(4194/1402) = 3 systematic fragments
            FLAG_HANDSHAKE → m=0 (no RLNC parity)
            Each fragment: ETH(14) + M13(48) + FragHdr(8) + chunk(≤1402)
          Returns NodeState::Handshaking
        TunWrite → stage_tun_write(tun_fd, ptr, len, bid)
          BID recycled to PBR after kernel consumes TUN write CQE
        Echo → build_echo_frame → seal_frame → sock.send
        HandshakeComplete → verify:                              [node/cryptography/handshake.rs]
          process_server_hello_node():
            Parse: ct(1568B), pk_hub(2592B), sig_hub(4627B)
            Transcript hash: SHA-512(client_nonce || ct || pk_hub)
            ML-DSA-87 verify_with_context(pk_hub, transcript, sig_hub)
              → Verify hub identity (prevents MITM)
            ML-KEM-1024 Decapsulate(dk_node, ct) → shared_secret
            HKDF-SHA-512(salt=client_nonce, IKM=shared_secret,
              info="M13-PQC-SESSION-KEY-v1", L=32) → session_key
            Return NodeHandshakeResult{session_key, pk_hub, transcript}
          LessSafeKey::new(AES_256_GCM, &session_key) installs cipher
          Build Finished message (4628B):
            [0] = HS_FINISHED (0x03)
            [1..4628] = ML-DSA-87 sign_deterministic(sk_node, transcript)
          send_fragmented_udp_rlnc(Finished, FLAG_CONTROL|FLAG_HANDSHAKE)
            k = ceil(4628/1402) = 4, m=0 (FLAG_HANDSHAKE)
          NodeState::Established
          setup_tunnel_routes(hub_ip):                           [node/network/datapath.rs]
            ip addr add 10.13.0.2/24 dev m13tun0
            ip link set m13tun0 up
            Detect default gateway via ip route show default
            ip route add <hub_ip>/32 via <gateway>
            ip route add 0.0.0.0/1 dev m13tun0 (split-default)
            ip route add 128.0.0.0/1 dev m13tun0
            Disable IPv6: net.ipv6.conf.all.disable_ipv6=1
            iptables -t nat -A POSTROUTING -o m13tun0 -j MASQUERADE
            MSS clamping: iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN
              -j TCPMSS --clamp-mss-to-pmtu
            TCP BDP tuning: sysctl net.ipv4.tcp_wmem/rmem max=16MB
            tc qdisc replace dev m13tun0 root fq
        HandshakeFailed → NodeState::Disconnected
        RekeyNeeded → NodeState::Registering → restart from registration
      BID recycled to PBR (unless deferred by TunWrite)
    Re-arm multishot recv if terminated (CQE_F_MORE == 0)
    Handshake micro-timeout: 250ms retransmit (HANDSHAKE_RETX_INTERVAL_NS)
      via send_fragmented_udp_rlnc()
    Keepalive: 100ms interval, pre-Established only
      verify guard + build_m13_frame(FLAG_CONTROL)
    Assembler GC: every 5 telemetry ticks (5-second stale expiry)
    Telemetry 1/sec:
      RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} State:{} Up:{}s
    reactor.submit() + submit_and_wait(0)
```

**6c — Cross-Component Data Flow Proof (README §4 Sequence Diagram + Phase 1/2):**

For each of the 8 lifecycle steps, open **both** the sender-side and receiver-side source files simultaneously and prove the data physically crosses:

| Step | Sender Function | Wire Data | Receiver Function | Proof Required |
|------|----------------|-----------|-------------------|----------------|
| 1. Registration | Node: `build_m13_frame(seq=0, flags=0x00)` → `sock.send()` | 62B cleartext: ETH(14) + M13(48) | Hub: `rx_parse_raw()` → `lookup_or_insert()` → PeerLifecycle::Registered | Verify Hub's M13 offset is `RAW_HDR_LEN` (42 = ETH 14 + IP 20 + UDP 8). Verify `flags=0x00` → no flag match → TxEnqueue but no session → registration only. |
| 2. Echo | Hub: `build_raw_udp_frame(FLAG_CONTROL)` → `enqueue_critical()` | 62B: ETH(14) + M13(48), flags=0x80 | Node: `process_rx_frame()` → `RxAction::NeedHandshakeInit` | Verify 100ms throttle guard. Verify Node checks `FLAG_CONTROL` AND `state == Registering`. |
| 3. ClientHello | Node: `initiate_handshake()` → `send_fragmented_udp()` | 4194B / 3 frags (⌈4194/1402⌉=3) | Hub: `Assembler::feed()` ×3 → `process_handshake_message()` → PQC SPSC → `process_client_hello_hub()` | Verify ClientHello layout: type(1) + version(1) + nonce(32) + ek(1568) + pk(2592) = 4194. Verify Hub extracts ek at `[34..1602]` and pk at `[1602..4194]`. Verify FLAG_HANDSHAKE → m=0 (no RLNC parity). |
| 4. ServerHello | Hub: Core 0 `process_client_hello_hub()` → PqcResp → `build_fragmented_raw_udp_rlnc()` | 8788B / 7 frags (⌈8788/1402⌉=7), m=0 | Node: `Assembler::feed()` ×7 → `process_server_hello_node()` | Verify ServerHello layout: type(1) + ct(1568) + pk_hub(2592) + sig_hub(4627) = 8788. Verify Node extracts ct at `[1..1569]`, pk at `[1569..4161]`, sig at `[4161..8788]`. Verify FLAG_HANDSHAKE → m=0 (no RLNC parity for handshakes). |
| 5. Finished | Node: `process_server_hello_node()` → `send_fragmented_udp_rlnc()` | 4628B / 4 frags (⌈4628/1402⌉=4), m=0 | Hub: `Assembler::feed()` ×4 → PQC SPSC → `process_finished_hub()` | Verify Finished layout: type(1) + sig_node(4627) = 4628. Verify Hub extracts sig at `[1..4628]`. Verify both sides compute identical transcript: `SHA-512(client_nonce \|\| ct \|\| pk_hub)`. |
| 6. HKDF Key | Both: `Hkdf::<Sha512>::new(Some(nonce), &shared_secret)` → `.expand(PQC_INFO, &mut key)` | — (internal) | Both | Verify HKDF parameters are **byte-identical** in `hub/cryptography/handshake.rs:174` and `node/cryptography/handshake.rs:174`: salt=session_nonce, IKM=shared_secret, info=`b"M13-PQC-SESSION-KEY-v1"` (constant `PQC_INFO` at hub:21, node:19), L=32. Any mismatch = silent AEAD failure at runtime. |
| 7. Upstream AEAD | Node: `seal_frame(cipher, seq, DIR_NODE_TO_HUB=0x01)` | AEAD tunnel frame | Hub: `open_frame(cipher, DIR_HUB_TO_NODE=0x00, offset=42)` | Verify nonce: `seq(8) \|\| dir(1) \|\| zeros(3)` at `frame[sig+20..sig+32]`. Node seals with `direction=0x01`, Hub opens with `our_dir=0x00` — reflection guard: `nonce_bytes[8]=0x01 ≠ 0x00` → passes. Verify AAD (4 bytes) and tag position (`sig+4..sig+20`) match both sides. Verify Hub `offset=42` (RAW_HDR_LEN for UDP peers). |
| 8. Downstream AEAD | Hub: `seal_frame(cipher, seq, DIR_HUB_TO_NODE=0x00, offset)` | AEAD tunnel frame | Node: `decrypt_batch_ptrs()` → `decrypt_one(cipher, DIR_NODE_TO_HUB=0x01)` | Mirror of Step 7. Hub seals with `direction=0x00`, Node opens with `our_dir=0x01` — reflection guard: `nonce_bytes[8]=0x00 ≠ 0x01` → passes. Verify Node uses `ETH_HDR_SIZE=14` as implicit offset. Verify `PRE_DECRYPTED_MARKER (0x02)` stamped at `frame[ETH_HDR_SIZE+2]` on success. |

> **Rule**: If any function body is missing, any call-site passes wrong arguments, any byte-range
> extraction mismatches the sender's layout, or any HKDF/nonce parameter differs between Hub
> and Node — the sprint MUST halt. The wiring defect must be fixed before deployment.



### 2.3 Report & Deploy

**Step 1 — Notify:** Inform the user that all code amendments for this sprint are complete.

**Step 2 — Report Audit Results:** Present the Integration Audit (Section 2.2) results:

| Audit Gate | Result |
|------------|--------|
| MIR Call-Graph Reachability | ✅ / ❌ (zero dead functions) |
| HIR Field-Level Validation | ✅ / ❌ (zero phantom fields) |
| Def-Use Semantic Liveness | ✅ / ❌ (zero dead stores) |
| Dependency Pruning | ✅ / ❌ (zero unused crates) |
| Test Suite | ✅ / ❌ (100% pass rate) |
| Scope Audit | ✅ / ❌ (zero deviations) |
| 6a: Hub Pipeline Trace | ✅ / ❌ (every call-site verified, parameters match, return values consumed) |
| 6b: Node Pipeline Trace | ✅ / ❌ (every call-site verified, CQE 3-pass wiring intact) |
| 6c: Cross-Component Data Flow | ✅ / ❌ (byte-range extractions match, HKDF parity, nonce symmetry) |

**Scope Audit:**

| Check | Question | Evidence Required |
|-------|----------|-------------------|
| **Under-delivery** | Did we skip anything from the sprint mandate? | Diff sprint card in `TODO.md` against files actually modified. Every "Files Modified" entry must have a corresponding code change. |
| **Over-delivery** | Did we change files or add features outside the sprint scope? | `git diff --stat` must not contain files unrelated to the sprint mandate. Unplanned changes must be explicitly justified or reverted. |
| **Deviation** | Did we implement something differently than what was agreed in Phase 1? | Compare the actual implementation against the Phase 1 literature findings. If we chose a different algorithm, data structure, or approach, document why and get user acknowledgment. |

**Empirical Proof Checklist:**

- [ ] `cargo build --release` with `-D dead_code -D unused` produces zero errors (MIR call-graph proof)
- [ ] `cargo build --release` with `-D unused_variables` produces zero errors (HIR field-level proof)
- [ ] `cargo build --release` with `-D unused_must_use -D unused_assignments` produces zero errors (Def-Use proof)
- [ ] `cargo +nightly udeps --workspace` reports zero unused dependencies
- [ ] `cargo test --workspace` achieves 100% pass rate
- [ ] No `#[allow(dead_code)]` added without explicit justification + sprint target for activation
- [ ] Scope audit: zero under-delivery, zero unjustified over-delivery, zero undocumented deviation

**Step 3 — Provide Commands:** Tell the user the exact commands to run for deployment and telemetry capture:

```bash
# Hub (remote):
T0=$(date +%s); cargo run --release 2>&1 | tee /tmp/m13_hub_$T0.log

# Node (local):
T0=$(date +%s); cargo run --release -- --hub <HUB_IP>:443 2>&1 | tee /tmp/m13_node_$T0.log

```

---

## Phase 3: Debugging — When Something Breaks

**Trigger**: Any invariant violation, unexpected behavior, or test failure.

### 3.1 Packet Lifecycle Trace

**First response to any data-plane issue**: trace the packet end-to-end.

```
1. Identify the symptom: which metric is wrong? (AEAD_FAIL > 0? Loss > expected? No RX?)
2. Locate the packet's entry point: Node TX or Hub RX?
3. Walk the datapath step by step:
   Node: build_m13_frame → seal_frame → sock.send → [WAN] → Hub: rx_parse_raw →
   classify → decrypt → tun_write → [TUN] → kernel → [TUN] → tun_read →
   seal_frame → build_raw_udp → AF_XDP TX → [WAN] → Node: CQE → open_frame → TUN write
4. At each stage, check: did the frame arrive? Is the counter incrementing?
5. Use hexdump (M13_HEXDUMP=1) to inspect wire bytes at entry/exit.
```

### 3.2 Process of Elimination

```
Hypothesis → Prediction → Test → Conclusion

Example:
  Hypothesis: "AEAD failures are caused by nonce reuse after rekey". Check Known Failure Vectors section of @OBSERVATIONS.md.
  Prediction: "If true, AEAD_FAIL should spike at exactly REKEY_FRAME_LIMIT"
  Test:       "Log seq_id at AEAD_FAIL events. Check if seq_id = 2^32"
  Conclusion: "Confirmed / Refuted. If refuted, next hypothesis."

Rules:
  - Never assume. Always verify with data.
  - Never fix two things at once. One variable per test.
  - Always capture telemetry BEFORE and AFTER the fix.
```

### 3.3 External Research (When Stuck)

If process of elimination exhausts local hypotheses:

1. **Search kernel / driver bugs**: Is this a known issue with the NIC, kernel version, or io_uring?
2. **Search crate issues**: Check GitHub issues for `io-uring`, `ml-kem`, `ml-dsa`, `ring`.
3. **Search academic literature**: Is the algorithm supposed to handle this edge case?
4. **Search Stack Overflow / mailing lists**: Has anyone else hit this with AF_XDP / SQPOLL?

Document every search and its result, even negative results ("searched X, found nothing relevant").

### 3.4 Fix Protocol

```
1. Identify root cause (not symptom).
2. Write the minimal fix.
3. cargo test --workspace  → 100% pass.
4. Deploy and capture telemetry.
5. Compare Before/After in OBSERVATIONS.md.
6. If invariants pass → fix accepted.
7. If invariants still violated → back to 3.1.
```

### 3.5 Rollback Protocol

**Trigger**: Sprint deployment regresses an invariant that was previously stable.

```
1. STOP. Do not attempt incremental fixes on a regressed deployment.
2. Revert to pre-sprint code:
     git stash        # if uncommitted changes
     git checkout HEAD~1 -- <files>   # or revert specific files
3. Rebuild and redeploy the pre-sprint binary.
4. Capture telemetry on the reverted binary — confirm invariants restored.
5. If invariants restored:
     Root cause is in the sprint changes. Diff the sprint changes
     against the working revert to isolate the regression.
6. If invariants NOT restored:
     Regression is environmental or pre-existing. Go to Phase 0
     and re-verify environment prerequisites.
7. Once root cause is identified, apply minimal fix and re-enter Phase 2.3.
```

> **Rule**: Never ship a sprint that regresses a previously-passing invariant.
> The rollback binary is the safety net.

---

## Phase 4: Post-Sprint — Document & Ship

**Trigger**: All Phase 2 acceptance criteria met. All Phase 3 issues resolved.

### 4.1 Update Documentation

| File | Action |
|------|--------|
| `README.md` | Update affected sSctions (architecture, wire protocol, connection lifecycle). Verify all line references still correct. |
| `TODO.md` | Mark sprint as `✅ COMPLETED`. Add date, files modified table, eradicated/added constructs, self-audit. Update blind spots if new telemetry gaps discovered. |
| `OBSERVATIONS.md` | Add new row to every Cross-Sprint Comparison table. Update Sprint-over-Sprint Δ. Fill in Network Quality if measured. Add per-sprint detail section with raw telemetry and analysis. |

### 4.2 Self-Audit Checklist

Before closing the sprint:

- [ ] All changed functions have correct doc comments
- [ ] No `TODO` or `FIXME` left without a sprint target
- [ ] No `unwrap()` on fallible paths without justification
- [ ] `cargo clippy --workspace` clean
- [ ] No dead code without `#[allow(dead_code)]` + comment explaining why preserved
- [ ] All line number references in docs verified against current source

### 4.3 Git Commit & Push

```bash
# Stage all changes:
git add -A

# Commit with sprint tag:
git commit -m "R-XXx: <one-line scope summary>

- <key change 1>
- <key change 2>
- Telemetry: AEAD OK/FAIL, Loss, Slab, HS
- Tests: N/N passing"

# Push:
git push origin main
```

### 4.4 Local Backup

After git push, create a local snapshot on the Desktop named after the sprint:

```bash
cp -r /home/m13/Desktop/m13 /home/m13/Desktop/backup/R-XX
```

Example: after Sprint R-02, the backup is `/home/m13/Desktop/R-02`.

### 4.5 Sprint Close

The sprint is closed when:

1. All 4.1 documentation updates are committed.
2. All 4.2 self-audit items are checked.
3. All 4.3 git operations complete.
4. All 4.4 local backup created.
5. `OBSERVATIONS.md` Cross-Sprint Comparison tables have the new row with **zero `—` cells** for metrics that were measurable this sprint.

---

## Quick Reference

```text
Phase 0 (Env)   → Verify kernel, hugepages, NIC, ulimits
Phase 1 (Pre)   → Research, fact-check, mutual agreement
Phase 2 (Exec)  → Code, audit wiring, test, deploy, capture telemetry
Phase 3 (Debug) → Trace datapath, eliminate hypotheses, fix, rollback if needed
Phase 4 (Post)  → README + TODO + OBSERVATIONS + git push
```

