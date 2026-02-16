# M13 Engineering Protocol

> **Purpose**: Codify the exact process for executing sprints. Every sprint follows these
> four phases in order. Skipping phases or reordering them is prohibited.

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

**6a — Hub Execution Pipeline (README §III.2):**

Open `hub/src/main.rs` and trace the following call chain. For each arrow (→), open the callee's source file and verify the function body exists, the parameters match what the caller passes, and the return value is consumed:

```
main()
  → run_executive(if_name, single_queue, tunnel)
    → BpfSteersman::load_and_attach(if_name) — open bpf.rs, verify it returns or panics (no Option)
    → create_tun("m13tun0") — open datapath.rs, verify TUN fd is returned and used
    → setup_nat() — verify called immediately after create_tun
    → SpscRing::new() ×4 — open spsc.rs, verify Producer/Consumer handles are created
    → thread::Builder::new().spawn(tun_housekeeping_thread) — verify:
        • tun_housekeeping_thread() exists and its signature matches the closure args
        • It blocks on OnceLock until UMEM base is published
        • Its main loop calls: free_slab drain → tun_fd write → tun_fd read → SPSC push
    → worker_entry(core_id, ...) — verify:
        • Engine::new_zerocopy() is called — open xdp.rs, verify AF_XDP bind occurs
        • umem_info.set() publishes UMEM base to TUN HK thread
        • FixedSlab::new() allocates slab — open runtime.rs, verify slab struct
        • Pre-stamp loop writes ETH+M13 headers into all slab frames

        VPP Main Loop — verify each graph node is actually invoked per iteration:
        • engine.recycle_tx() + engine.refill_rx() — open xdp.rs, verify both exist
        • execute_tx_graph() → tun_read_batch() — open datapath.rs, verify:
            ◦ free_to_dp_cons.pop_batch() feeds slab.free()
            ◦ free_to_tun_prod pushes provisioned slab IDs
            ◦ rx_tun_cons.pop_batch() injects pre-built TUN frames
        • engine.poll_rx() → PacketVector — verify poll_rx returns batch
        • scatter() classifies packets — open network/mod.rs, verify scatter logic
        • rx_parse_raw() — open datapath.rs, verify:
            ◦ Extracts src_ip/src_port from IP/UDP header offsets
            ◦ Calls peers.lookup_or_insert() — open protocol.rs, verify PeerTable method
            ◦ Routes by crypto_ver: 0x00 → cleartext, 0x01 → decrypt
        • aead_decrypt_vector() — open aead.rs, verify batch decrypt exists
        • classify_route() — verify FLAG dispatch: CONTROL→Consumed, FRAGMENT→Handshake, TUNNEL→TunWrite
        • tun_write_vector() — verify SPSC push to TUN HK or VFS fallback
        • handle_handshake_packet() — verify:
            ◦ FragHeader parsed (msg_id, index, total, offset, len)
            ◦ Assembler::feed() called — verify closure-based API matches current signature
            ◦ On reassembly complete: process_handshake_message() dispatches by msg_type
        • seal_frame() — open aead.rs, verify nonce construction: seq_id(8)||direction(1)||zeros(3)
        • build_raw_udp_frame() / build_fragmented_raw_udp() — verify frame construction
        • scheduler.enqueue_critical() — open protocol.rs, verify enqueue method exists
        • Telemetry 1/sec print — verify format string matches documented counters
```

**6b — Node Execution Pipeline (README §III.4):**

Open `node/src/main.rs` and trace:

```
main()
  → create_tun("m13tun0") — open datapath.rs, verify TUN fd returned
  → run_uring_worker(hub_addr, echo, hexdump, tun_file)
    → calibrate_tsc() — open runtime.rs, verify TSC calibration
    → tune_system_buffers() — verify sysctl writes (rmem_max, wmem_max)
    → UdpSocket::bind → connect(hub_addr)
    → UringReactor::new(raw_fd, cpu) — open uring_reactor.rs, verify:
        ◦ HugeTLB mmap allocates 2MB-aligned arena
        ◦ IoUring::builder().setup_sqpoll() configures SQPOLL
        ◦ IORING_REGISTER_PBUF_RING syscall registers PBR
        ◦ arm_multishot_recv() arms the lifetime SQE
    → build_m13_frame(FLAG_CONTROL) — open protocol.rs, verify frame builder
    → sock.send(&reg) — registration frame sent

    CQE Three-Pass Main Loop — verify each pass is actually coded:
    Pass 0 (CQE Drain + Classify):
        • reactor.ring.completion().sync() — verify CQE drain
        • TAG_UDP_RECV_MULTISHOT → collects recv_bids/recv_lens
        • TAG_TUN_READ → build_m13_frame → seal_frame → stage_udp_send
        • TAG_TUN_WRITE → recycles BID to PBR
        • TAG_UDP_SEND_TUN/ECHO → arm_tun_read(bid)

    Pass 1 (Vectorized AEAD Batch Decrypt):
        • Guard: Established AND recv_count > 0
        • Scans for crypto_flag == 0x01 → collects enc_ptrs
        • decrypt_batch_ptrs() — open aead.rs, verify 4-wide AES-NI pipeline
        • Stamps PRE_DECRYPTED_MARKER (0x02) on success
        • Rekey check: frame_count >= limit || time > limit

    Pass 2 (Per-Frame RxAction Dispatch):
        • process_rx_frame() returns RxAction — verify enum variants:
            ◦ NeedHandshakeInit → initiate_handshake() — open handshake.rs, verify:
                · ML-KEM-1024 keygen (dk, ek)
                · ML-DSA-87 keygen (sk, pk)
                · OsRng nonce (32 bytes)
                · send_fragmented_udp() called with ClientHello payload
                · Returns NodeState::Handshaking
            ◦ TunWrite → stage_tun_write(tun_fd, ptr, len, bid)
            ◦ Echo → build_echo_frame → seal_frame → sock.send
            ◦ HandshakeComplete → verify:
                · process_handshake_node() — open handshake.rs, verify:
                    - ML-KEM decapsulate(ct) → shared secret
                    - SHA-512(CH || ct) transcript → pk_hub.verify()
                    - HKDF-SHA-512(nonce, ss) → session_key
                    - SHA-512(CH || SH) → sign → Finished payload
                · LessSafeKey::new(AES_256_GCM, &key) installs cipher
                · setup_tunnel_routes() — open datapath.rs, verify ip rule/route commands
            ◦ HandshakeFailed → NodeState::Disconnected
            ◦ RekeyNeeded → NodeState::Registering
        • BID recycled to PBR (unless deferred)
    • Keepalive: 100ms, pre-Established only — verify guard + build_m13_frame(FLAG_CONTROL)
    • Telemetry 1/sec — verify format string matches documented counters
```

**6c — Cross-Component Data Flow Proof (README §IV):**

For each of the 7 lifecycle steps, open **both** the sender-side and receiver-side source files simultaneously and prove the data physically crosses:

| Step | Sender Function | Wire Data | Receiver Function | Proof Required |
|------|----------------|-----------|-------------------|----------------|
| 0 | Node: `build_m13_frame(FLAG_CONTROL)` → `sock.send()` | 62B cleartext | Hub: `rx_parse_raw()` → `lookup_or_insert()` | Verify Hub's M13 offset (56 bytes into UDP) matches Node's frame layout. Verify `FLAG_CONTROL` → `Consumed` (no echo). |
| 1 | Node: `initiate_handshake()` → `send_fragmented_udp()` | 4194B / 3 frags | Hub: `Assembler::feed()` ×3 → `process_client_hello_hub()` | Verify fragment MTU (1402) produces exactly ⌈4194/1402⌉ = 3 fragments. Verify `Assembler` closure receives correct offsets. Verify `process_client_hello_hub` extracts ek at `[34..1602]` and pk at `[1602..4194]` — byte ranges must match `initiate_handshake` layout. |
| 2 | Hub: `process_client_hello_hub()` → `build_fragmented_raw_udp()` | 8788B / 7 frags | Node: `Assembler::feed()` ×7 → `process_handshake_node()` | Verify ServerHello layout: type(1) + ct(1568) + pk(2592) + sig(4627) = 8788. Verify Node extracts ct at `[1..1569]`, pk at `[1569..4161]`, sig at `[4161..8788]` — must match Hub's construction. |
| 3 | Node: `process_handshake_node()` → `send_fragmented_udp()` | 4628B / 4 frags | Hub: `Assembler::feed()` ×4 → `process_finished_hub()` | Verify Finished layout: type(1) + sig(4627) = 4628. Verify Hub extracts sig at `[1..4628]`. Verify both sides compute identical transcripts: `SHA-512(CH \|\| SH)`. |
| 4 | Both: `HKDF-SHA-512(nonce, ss, "M13-PQC-SESSION-KEY-v1")` | — | Both | Verify HKDF parameters (salt, IKM, info string, output length=32) are **byte-identical** in `hub/src/cryptography/handshake.rs` and `node/src/cryptography/handshake.rs`. Any mismatch = silent AEAD failure. |
| 5 | Node: `seal_frame(cipher, seq, DIR_NODE_TO_HUB)` | AEAD tunnel | Hub: `open_frame(cipher, DIR_HUB_TO_NODE)` | Verify nonce construction is mirror-symmetric: Node seals with `direction=0x01`, Hub opens expecting `direction != 0x00` (reflection guard). Verify AAD bytes (4) and tag position (offset+4..+20) match on both sides. |
| 6 | Hub: `seal_frame(cipher, seq, DIR_HUB_TO_NODE)` | AEAD tunnel | Node: `open_frame(cipher, DIR_NODE_TO_HUB)` | Same mirror verification as Step 5, reversed direction. |

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
  Hypothesis: "AEAD failures are caused by nonce reuse after rekey"
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

