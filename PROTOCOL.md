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

1. Read the sprint card in `TODO.md` — scope, mandate, files affected.
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
| **Industry Practice** | How do WireGuard, Cloudflare, Meta, Google handle the same problem? |
| **Crate Documentation** | `docs.rs` for any new dependency — verify API correctness, not just examples |

### 1.3 Context-Appropriate Adjustment

Not every industry practice applies to M13. Filter through:

- **Deployment context**: Single-Node satellite uplink, not datacenter. Latency > 20ms, loss > 1%.
- **Threat model**: Post-quantum adversary, contested spectrum. Not just TLS web traffic.
- **Hardware constraints**: ARM Cortex-A76 (4-wide OoO), not Xeon. NEON, not AVX-512.
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

### 1.5 Baseline Capture

**Before writing any code**, capture telemetry on the current (pre-sprint) binary.
This becomes the "before" in before/after comparison.

```bash
# Deploy current code (no sprint changes yet):
# Hub + Node as per Phase 2.4 commands.
# Capture 60s telemetry + ping + iperf3.
# Save logs: /tmp/m13_baseline_R-XXx_hub.log, /tmp/m13_baseline_R-XXx_node.log
```

> **Why**: The previous sprint's "after" may have been captured days/weeks ago on
> different WAN conditions or kernel versions. A fresh baseline on the same environment
> makes the before/after comparison valid.

---

## Phase 2: Execution — Apply Changes & Test

**Trigger**: Phase 1 approval received.

### 2.1 Implementation Order

1. **Dependencies first**: New crates, new modules, new types.
2. **Core logic**: The actual algorithm / data structure / protocol change.
3. **Integration**: Wire into existing call sites, update state machines.
4. **Tests**: Unit tests for new code, integration tests for changed paths.

### 2.2 Build Verification

```bash
# Must pass before any deployment:
cargo build --release 2>&1 | tail -5          # Zero warnings
cargo test  --workspace 2>&1 | tail -5        # 100% pass rate
```

### 2.3 Integration Audit

**Before deployment, prove that every change is wired and alive — not orphan code.**

#### Wiring Proof

For every new function, struct, or module added in this sprint:

```
1. grep -rn "function_name" --include="*.rs" → must appear in at least one call site
   outside its own definition. If it only appears in its declaration, it is dead code.
2. If the new code emits to a telemetry counter, verify the counter increments:
   - Deploy briefly (10s), check 1/sec telemetry line, confirm the counter moves.
   - Counter stuck at 0 = code path never reached = wiring failure.
3. If the new code is a data structure (e.g., SPSC ring), verify both producer
   AND consumer are wired:
   - Producer: grep for push/enqueue calls.
   - Consumer: grep for pop/dequeue calls.
   - Missing either side = structure exists but does nothing.
```

#### Scope Audit

Compare what was actually changed against the Phase 1 agreed scope:

| Check | Question | Evidence Required |
|-------|----------|-------------------|
| **Under-delivery** | Did we skip anything from the sprint mandate? | Diff sprint card in `TODO.md` against files actually modified. Every "Files Modified" entry must have a corresponding code change. |
| **Over-delivery** | Did we change files or add features outside the sprint scope? | `git diff --stat` must not contain files unrelated to the sprint mandate. Unplanned changes must be explicitly justified or reverted. |
| **Deviation** | Did we implement something differently than what was agreed in Phase 1? | Compare the actual implementation against the Phase 1 literature findings. If we chose a different algorithm, data structure, or approach, document why and get user acknowledgment. |

#### Empirical Proof Checklist

- [ ] Every new `pub fn` has at least one call site (grep proof)
- [ ] Every new `pub struct` is instantiated somewhere (grep proof)
- [ ] Every new module is `pub mod` registered AND imported (grep proof)
- [ ] Telemetry counters for new code paths are non-zero after brief deployment
- [ ] No `#[allow(dead_code)]` added without explicit justification + sprint target for activation
- [ ] Scope audit: zero under-delivery, zero unjustified over-delivery, zero undocumented deviation

### 2.4 Deployment & Telemetry Capture

```bash
# Hub (remote):
T0=$(date +%s); cargo run --release 2>&1 | tee /tmp/m13_hub_$T0.log

# Node (local):
T0=$(date +%s); cargo run --release -- --hub <HUB_IP>:443 2>&1 | tee /tmp/m13_node_$T0.log

# Wait for Established state, then measure:
ping -c 100 <hub_tun_ip>
iperf3 -c <hub_tun_ip> -t 30
iperf3 -c <hub_tun_ip> -u -b 50M -t 30
```

### 2.5 Acceptance Criteria

All invariants from `OBSERVATIONS.md` must hold:

- [ ] `AEAD_FAIL = 0`
- [ ] `Internal Loss = 0`
- [ ] `HS_FAIL = 0`
- [ ] `Reconnections = 0` (no unplanned drops)
- [ ] `Test Pass Rate = 100%`
- [ ] `|ΔSlab| ≤ ε` (no slab leak)

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
| `README.md` | Update affected sections (architecture, wire protocol, connection lifecycle). Verify all line references still correct. |
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
cp -r /home/m13/Desktop/m13 /home/m13/Desktop/R-XX
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

