# Intern task: Investigate mbedTLS slowdown in `torture_threads_pki_rsa` (esp. under Valgrind)

## Goal

Figure out **why libssh + mbedTLS is much slower than OpenSSL/libgcrypt** on the threaded RSA PKI unit test, and why Valgrind on Fedora/mbedTLS 3 turns that into a ~1500s timeout.

This is an **investigation / root-cause** task, not a production fix. Upstream maintainers asked for insight into whether this is a known mbedTLS issue or something about how libssh uses mbedTLS.

Deliverable: a short write-up with measurements, ranked hypotheses that were confirmed/rejected, and (optional) a minimal patch or CI tweak recommendation.

---

## Background / original upstream question

Thread on the mbedTLS v4 migration RFC MR:

- **MR:** https://gitlab.com/libssh/libssh-mirror/-/merge_requests/846
- **Original comment (Jakub Jelen / @jjelen):** https://gitlab.com/libssh/libssh-mirror/-/merge_requests/846#note_3704553687

### Original comment (verbatim)

> I have one partially related observation regarding the mbedtls. Recently the `torture_threads_pki_rsa` test started timing out under valgrind with mbedtls (with version 3 on Fedora). It takes almost **1500 seconds** to finish, while OpenSSL and Libgcrypt versions takes roughly half or 1/3 of the time.
>
> When looking at the test in different configurations (last master run, without valgrind), I can not unnotice the mbedtls does not perform very well under the threads and its not improving with versions (comparing across different distros and configurations, so the numbers are not really hard, but performance in order of magnitude from the openssl does not sounds like a fluke):
>
> | Backend | Time (approx, no Valgrind) |
> |---|---|
> | openssl 1.1.1 | 7s |
> | openssl 3.5 | 7s |
> | libgcrypt | 30s |
> | libressl | 15s |
> | mbedtls 2.\* | 29s |
> | mbedtls 3.\* | 45s |
> | mbedtls 4.\* | 80s |
>
> @david-cermak You seem to have some overview about the mbedTLS. Do you know if this is some known issue or something that could be tuned in the way how libssh is using the mbedtls?

### Follow-up from Jakub (release-branch comparison)

> … valgrind run on **0.12** goes to **700s** on mbedtls 3 with valgrind and **27s** without, which is comparable to mbedtls 2 so it might be related to the v4 changes:
>
> - Valgrind (mbedTLS 3, libssh 0.12): https://gitlab.com/libssh/libssh-mirror/-/jobs/15574341083
> - Without Valgrind (mbedTLS 3, libssh 0.12): https://gitlab.com/libssh/libssh-mirror/-/jobs/15574341066

### David’s experiment outcome (so far)

Hypothesis of **shared global CTR-DRBG lock contention** was tested and **does not fully explain the Valgrind timeout**:

> After some experiments it looks like I was wrong, valgrind still timeouts after making the context thread local → https://gitlab.com/david-cermak/libssh-mirror/-/jobs/16154737437 (passed after retry, but took ~**1281.83 sec**)

So: per-thread DRBG may still help a bit (or not), but the dominant cost remains something else (likely RSA keygen / MPI work under Valgrind).

---

## Related merge requests / branches

| Item | Link |
|---|---|
| Original discussion MR (mbedTLS v4 RFC) | https://gitlab.com/libssh/libssh-mirror/-/merge_requests/846 |
| Original note | https://gitlab.com/libssh/libssh-mirror/-/merge_requests/846#note_3704553687 |
| WIP experiment MR (per-thread DRBG) | https://gitlab.com/libssh/libssh-mirror/-/merge_requests/876 |
| Experiment branch | `david/test/drbg` → https://gitlab.com/david-cermak/libssh-mirror/-/tree/test/drbg |
| Upstream mirror | https://gitlab.com/libssh/libssh-mirror |

Experiment commit idea (WIP / ugly on purpose):

- Message: `fix: test if drbg context sharing was a test/bottleneck`
- Toggle: set env `LIBSSH_PER_THREAD_DRBG=1` to use per-thread DRBG (pthread TLS); unset = old global DRBG behavior.

---

## What the failing / slow test does

File: `tests/unittests/torture_threads_pki_rsa.c`

- Spawns **`NUM_THREADS = 10`** pthreads for many PKI operations (import/export/dup/cert/…).
- Heaviest case: `thread_pki_rsa_generate_key` — each thread generates **RSA 1024 + 2048 + 4096**, then sign/verify.
- Also has `torture_mixed` which runs **11 workloads × 10 threads** concurrently.

This is intentionally stressful for RNG + RSA keygen under concurrency.

---

## How libssh uses mbedTLS RNG today (important code)

libssh keeps a **process-wide** entropy + CTR-DRBG and passes it into almost all mbedTLS PKI/crypto RNG call sites via:

```c
SSH_MBEDTLS_RNG     = mbedtls_ctr_drbg_random
SSH_MBEDTLS_RNG_CTX = ssh_get_mbedtls_ctr_drbg_context()
```

Key files:

- `src/libmbedcrypto.c` — `ssh_crypto_init()` seeds global DRBG; getter lives here on master
- `src/getrandom_mbedcrypto.c` — `ssh_mbedtls_random()` / DRBG symbol
- `src/pki_mbedcrypto.c` — `mbedtls_rsa_gen_key()`, `mbedtls_pk_sign()`, key parse (mbedTLS 3+ needs RNG), etc.
- `src/threads/mbedtls.c` — wires `MBEDTLS_THREADING_PTHREAD` / `MBEDTLS_THREADING_ALT`
- `include/libssh/libmbedcrypto.h` — `SSH_MBEDTLS_RNG` / `SSH_MBEDTLS_RNG_CTX` macros

With distro mbedTLS built with threading, the **global DRBG is mutex-protected**, so concurrent RSA gen/sign can serialize on RNG.

---

## Hypotheses already sketched (investigate / rank with data)

Use these as a checklist. The DRBG experiment already weakens #1 as the *sole* Valgrind cause, but still measure it.

### 1. Global CTR-DRBG shared by all threads (lock contention)
- All threads call `mbedtls_ctr_drbg_random()` on one context.
- Under Valgrind, hold times explode → near-serial execution.
- **Experiment status:** per-thread DRBG (`LIBSSH_PER_THREAD_DRBG=1`) still ~1280s under Valgrind → **not the only / main cause of the timeout**.

### 2. Software-only RSA / MPI vs OpenSSL assembly
- mbedTLS RSA is portable C; OpenSSL has tuned ASM on x86_64.
- Valgrind penalizes pure-C big-integer loops far more than optimized ASM.
- Fits: OpenSSL ~7s, mbedTLS 3 ~45s, Valgrind → minutes.

### 3. mbedTLS 3+/4+ API overhead in libssh wrappers
- From mbedTLS 3, libssh often does `mbedtls_rsa_export` → `import` → `complete` instead of direct `mbedtls_mpi_copy` (see `pki_key_dup` / `pki_key_compare` in `pki_mbedcrypto.c`).
- Matches observed trend: 2.\* 29s → 3.\* 45s → 4.\* 80s (non-Valgrind).

### 4. Stronger constant-time / side-channel mitigations in newer mbedTLS
- Blinding, constant-time MPI, etc. trade speed for safety.
- Especially expensive under Valgrind.

### 5. Allocation churn + Valgrind instrumentation
- Extra export/import temporaries + many threads × subtests → Valgrind memcheck cost.
- May turn “slow” into “timeout” without a deadlock.

### Also note (orthogonal CI noise)
- OpenSSL FIPS CentOS jobs failing `torture_threads_crypto` / `torture_threads_pki_rsa` are **unrelated** to this mbedTLS issue (different crypto backend). Do not chase those for this task unless asked.

---

## Suggested investigation plan

### A. Reproduce locally (preferred) or in CI

Podman image used before (has mbedTLS; version may be 4.x on tumbleweed — prefer Fedora/CentOS image with **mbedTLS 3** to match Jakub’s report):

```text
registry.gitlab.com/libssh/build-images:buildenv-tumbleweed
```

Build with mbedTLS + unit tests:

```bash
cmake .. -DWITH_MBEDTLS=ON -DWITH_GCRYPT=OFF -DUNIT_TESTING=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build . --target torture_threads_pki_rsa -j"$(nproc)"
```

Baseline timings:

```bash
# no valgrind
/usr/bin/time -p ./tests/unittests/torture_threads_pki_rsa

# with valgrind (expect very long)
/usr/bin/time -p valgrind --tool=memcheck ./tests/unittests/torture_threads_pki_rsa
```

Compare against OpenSSL build of the same test if possible.

### B. Isolate keygen vs “everything else”

Temporarily comment out / skip `thread_pki_rsa_generate_key` (and/or 4096-bit only) in `torture_threads_pki_rsa.c` and re-time:

- If most of the time disappears → **RSA keygen/MPI**, not DRBG contention alone.
- If still slow with only import/dup/sign → look at export/import paths and RNG.

Also compare:

- single-threaded `torture_pki_rsa` vs threaded `torture_threads_pki_rsa` on mbedTLS.

### C. Re-check per-thread DRBG (already sketched)

Experiment MR: https://gitlab.com/libssh/libssh-mirror/-/merge_requests/876

A/B on same binary:

```bash
/usr/bin/time -p ./tests/unittests/torture_threads_pki_rsa
/usr/bin/time -p env LIBSSH_PER_THREAD_DRBG=1 ./tests/unittests/torture_threads_pki_rsa
```

Expect:
- large speedup under threads **only if** DRBG lock was hot;
- little change if RSA compute dominates (consistent with current CI evidence).

**Gotcha found during the experiment:** override shared libs (`tests/external_override/`) compile `getrandom_mbedcrypto.c` **without** `libmbedcrypto.c`. If you `extern` a symbol defined only in `libmbedcrypto.c` (e.g. `ssh_mbedtls_entropy`), `torture_override` fails with:

```text
undefined symbol: ssh_mbedtls_entropy
```

Keep entropy/DRBG definitions in the same TU that override libs compile, or link appropriately.

### D. Profile (to prove the hot path)

Without Valgrind first:

```bash
perf record -g ./tests/unittests/torture_threads_pki_rsa
perf report
```

Look for time in:
- `mbedtls_mpi_*` / `mbedtls_rsa_gen_key` / primality
- `mbedtls_ctr_drbg_random` / `mbedtls_entropy_func` / mutex wait
- `mbedtls_rsa_export` / `mbedtls_rsa_complete`

Under threads, also try:

```bash
perf record -e 'syscalls:sys_enter_futex' -g -- ./tests/unittests/torture_threads_pki_rsa
```

or thread-aware tools (`perf`, `mutrace`, `valgrind --tool=helgrind` carefully — helgrind will be even slower).

### E. Version bisect (optional)

Jakub’s 0.12 numbers (~27s / ~700s Valgrind) vs master (~45s / ~1500s) suggest **master got worse**. Possible causes:

- mbedTLS 3→4 migration work / `#if MBEDTLS_VERSION_MAJOR > 2` paths in `pki_mbedcrypto.c`
- more work in the threaded test itself
- distro mbedTLS config differences

Bisect or compare `pki_mbedcrypto.c` RSA paths between 0.12 and master on the same mbedTLS 3 package.

---

## Success criteria

A good intern write-up answers:

1. **Where does the time go?** (keygen MPI vs DRBG locks vs export/import vs Valgrind overhead)
2. **Is libssh mis-using mbedTLS?** (e.g. unnecessary global DRBG, avoidable export/import, missing compile-time options) **or** is this inherent mbedTLS software RSA + Valgrind?
3. **What should upstream do?** Concrete options, e.g.:
   - raise Valgrind timeout for this test on mbedTLS;
   - skip/reduce 4096-bit keygen under Valgrind;
   - document that mbedTLS RSA keygen is expected to be slower;
   - optional real fix (per-thread DRBG, reduce export/import churn) **only if** data supports it.

Do **not** merge the WIP TLS-DRBG experiment as-is; it was only for measurement.

---

## Quick reference links

- Discussion: https://gitlab.com/libssh/libssh-mirror/-/merge_requests/846#note_3704553687
- Experiment MR: https://gitlab.com/libssh/libssh-mirror/-/merge_requests/876
- Valgrind still slow with TLS DRBG: https://gitlab.com/david-cermak/libssh-mirror/-/jobs/16154737437
- libssh 0.12 mbedTLS3 Valgrind: https://gitlab.com/libssh/libssh-mirror/-/jobs/15574341083
- libssh 0.12 mbedTLS3 no Valgrind: https://gitlab.com/libssh/libssh-mirror/-/jobs/15574341066
- Test source: `tests/unittests/torture_threads_pki_rsa.c`
- mbedTLS PKI backend: `src/pki_mbedcrypto.c`
- mbedTLS crypto init / DRBG: `src/libmbedcrypto.c`, `src/getrandom_mbedcrypto.c`
- Threading glue: `src/threads/mbedtls.c`
