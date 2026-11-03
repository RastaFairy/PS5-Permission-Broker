/*
 * PS5 Permission Broker - FW 5.50 baseline
 *
 * One resident consumer for the legacy etaHEN/OnionHEN app-jailbreak marker.
 * This deliberately does NOT install global kernel hooks and cannot stop an
 * unrelated binary from writing credentials directly. Competing marker
 * consumers must be removed/disabled as documented in README.md.
 *
 * Race hardening ("win the marker race"):
 *  - Atomic claim: an incoming marker is rename()d to a private ".pb_claim_*"
 *    name inside the same directory the instant it is seen. Competing
 *    consumers stat only the canonical names, so from claim time they are
 *    blind to the request; the claim is processed at leisure and unlinked.
 *  - Reactive wake-up: each sandbox download0 directory is watched with a
 *    kqueue EVFILT_VNODE knote; events wake the scan immediately instead of
 *    waiting for the poll tick. If kqueue is unavailable or misbehaves the
 *    loop silently degrades to a pure 2 ms poll (never worse than polling).
 *  - Orphan recovery: claims left on disk by a previous crash are processed
 *    on every sweep, so a restart cannot strand a request.
 *  - Policy audit: every ~5 s the process list is walked and any process
 *    running with the app-jailbreak authid outside the allowlist is logged,
 *    exposing a race lost to another consumer.
 */
#include <hijacker.hpp>
#include <kernel/proc.hpp>
#include <util.hpp>

extern "C" {
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ps5/payload.h>
#include <ps5/kernel.h>
#include <ps5/klog.h>
}

extern "C" uint64_t kernel_base = 0;

namespace {
constexpr const char *kVersion = "0.4.0-fw550";
constexpr const char *kSandboxRoot = "/mnt/sandbox";
constexpr const char *kStateDir = "/data/permission-broker";
constexpr const char *kAllowlist = "/data/permission-broker/allowlist.txt";
constexpr const char *kLockFile = "/data/permission-broker/authority.lock";
constexpr const char *kLogFile = "/data/permission-broker/broker.log";
constexpr const char *kPidFile = "/data/permission-broker/broker.pid";
constexpr const char *kProcessName = "perm-broker";
constexpr size_t kMaxLogBytes = 256 * 1024; // rotate broker.log past this size
constexpr const char *kFlagKqueue = "/data/permission-broker/use-kqueue";
constexpr const char *kFlagAudit = "/data/permission-broker/use-audit";
constexpr uint64_t kAppJailbreakAuthId = 0x4801000000000013ull;
constexpr unsigned kPollIntervalUs = 2000;        // fallback sweep every 2 ms
constexpr unsigned kMaxDeferredAttempts = 5000;   // 10 s at 2 ms
constexpr unsigned kAuditEveryLoops = 2500;       // ~5 s between audits
constexpr size_t kMaxMarkerBytes = 1024;
constexpr size_t kMaxClaimsPerSweep = 64;
constexpr int kMaxWatches = 32;
constexpr const char *kClaimPrefix = ".pb_claim_";

const char *kMarkerNames[] = {
    "etahen_jailbreak",
    "onionhen_jailbreak",
};

int g_lockFd = -1;
int g_kq = -1;
unsigned g_claimSeq = 0;
unsigned long g_loops = 0;

struct RetryEntry {
    char path[512];
    unsigned attempts;
};
RetryEntry g_retries[64]{};

struct WatchEntry {
    int fd = -1;
    char slot[16]{};
};
WatchEntry g_watches[kMaxWatches]{};

void log_line(const char *fmt, ...) {
    char msg[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    klog_printf("[perm-broker] %s\n", msg);

    // Self-cleaning: keep the log bounded by rotating to broker.log.1
    // (one previous generation) when it outgrows kMaxLogBytes.
    struct stat lst{};
    if (stat(kLogFile, &lst) == 0 && lst.st_size > static_cast<off_t>(kMaxLogBytes)) {
        char old[512];
        if (snprintf(old, sizeof(old), "%s.1", kLogFile) <
            static_cast<int>(sizeof(old))) {
            unlink(old);
            (void)rename(kLogFile, old);
        }
    }

    int fd = open(kLogFile, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd >= 0) {
        (void)write(fd, msg, strnlen(msg, sizeof(msg)));
        (void)write(fd, "\n", 1);
        close(fd);
    }
}

bool ensure_state_dir() {
    if (mkdir(kStateDir, 0700) != 0 && errno != EEXIST) {
        log_line("cannot create %s: errno=%d", kStateDir, errno);
        return false;
    }
    (void)chmod(kStateDir, 0700);
    return true;
}

// Optional features are gated by the presence of a marker file; both touch
// mechanisms that are unproven on some firmwares and stay OFF by default.
bool config_flag(const char *path) {
    struct stat st{};
    return stat(path, &st) == 0;
}

bool acquire_single_instance() {
    g_lockFd = open(kLockFile, O_RDWR | O_CREAT, 0600);
    if (g_lockFd < 0) {
        log_line("cannot open instance lock: errno=%d", errno);
        return false;
    }
    // flock(2) is not exported by the PS5 libkernel stubs; fcntl(F_SETLK) is
    // the equivalent whole-file advisory lock and is released on process exit.
    struct flock fl{};
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    if (fcntl(g_lockFd, F_SETLK, &fl) != 0) {
        log_line("another Permission Broker instance owns the lock; exiting");
        close(g_lockFd);
        g_lockFd = -1;
        return false;
    }
    return true;
}

bool valid_slot_name(const char *name, char tid[12]) {
    const size_t n = strlen(name);
    size_t split = 0;
    while (split < n && name[split] != '_') {
        const unsigned char c = static_cast<unsigned char>(name[split]);
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z'))) return false;
        ++split;
    }
    if (split < 4 || split > 10 || split >= n || name[split] != '_') return false;
    const size_t digits = n - split - 1;
    if (digits < 1 || digits > 4) return false;
    for (size_t i = split + 1; i < n; ++i) {
        if (name[i] < '0' || name[i] > '9') return false;
    }
    memcpy(tid, name, split);
    tid[split] = '\0';
    return true;
}

bool title_in_file(const char *path, const char *tid) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char row[128];
    bool found = false;
    while (fgets(row, sizeof(row), f)) {
        char *p = row;
        while (*p == ' ' || *p == '\t') ++p;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        char *end = p;
        while (*end && *end != '\r' && *end != '\n' && *end != ' ' &&
               *end != '\t' && *end != '#') ++end;
        const size_t len = static_cast<size_t>(end - p);
        if (len == strlen(tid) && strncmp(p, tid, len) == 0) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

bool is_allowed_title(const char *tid) {
    // Keep existing OnionHEN deployments working without forcing users to
    // recreate their legacy allowlist. The dedicated broker list remains the
    // preferred, auditable source; /data/whitelist.txt is a compatibility
    // fallback matching the helper observed in the supplied KLOG.
    return title_in_file(kAllowlist, tid) || title_in_file("/data/whitelist.txt", tid);
}

bool create_default_allowlist() {
    struct stat st{};
    if (stat(kAllowlist, &st) == 0) return true;
    int fd = open(kAllowlist, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return errno == EEXIST;
    static const char defaults[] =
        "# Explicitly approved homebrew title IDs only. One ID per line.\n"
        "# These two IDs are the PS5SX2/helper IDs observed in your KLOG.\n"
        "PPSA99203\n"
        "PPSA99303\n";
    const ssize_t n = write(fd, defaults, sizeof(defaults) - 1);
    close(fd);
    return n == static_cast<ssize_t>(sizeof(defaults) - 1);
}

int parse_pid(const char *json) {
    const char *p = strstr(json, "\"PID\"");
    if (!p || !(p = strchr(p + 5, ':'))) return -1;
    ++p;
    while (*p == ' ' || *p == '\t' || *p == '"') ++p;
    errno = 0;
    char *end = nullptr;
    const long v = strtol(p, &end, 10);
    if (errno != 0 || end == p || v <= 1 || v > 0x7fffffffL) return -1;
    while (*end == ' ' || *end == '\t' || *end == '"' || *end == '\r' || *end == '\n') ++end;
    if (*end != '\0' && *end != ',' && *end != '}') return -1;
    return static_cast<int>(v);
}

int read_marker(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st{};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        static_cast<size_t>(st.st_size) > cap - 1) {
        close(fd);
        return -1;
    }
    const ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return static_cast<int>(n);
}

unsigned retry_count(const char *path) {
    for (auto &entry : g_retries) {
        if (entry.path[0] && strcmp(entry.path, path) == 0) {
            if (entry.attempts < 1000000) ++entry.attempts;
            return entry.attempts;
        }
    }
    for (auto &entry : g_retries) {
        if (!entry.path[0]) {
            snprintf(entry.path, sizeof(entry.path), "%s", path);
            entry.attempts = 1;
            return 1;
        }
    }
    return kMaxDeferredAttempts;
}

void clear_retry(const char *path) {
    for (auto &entry : g_retries) {
        if (entry.path[0] && strcmp(entry.path, path) == 0) {
            entry.path[0] = '\0';
            entry.attempts = 0;
        }
    }
}

void write_status(const char *slot, const char *status, int pid) {
    char path[512];
    if (snprintf(path, sizeof(path), "%s/%s.status", kStateDir, slot) >=
        static_cast<int>(sizeof(path))) return;
    char body[256];
    const int len = snprintf(body, sizeof(body), "status=%s\npid=%d\n", status, pid);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        (void)write(fd, body, static_cast<size_t>(len));
        close(fd);
    }
}

enum class Result {
    Granted,
    AlreadyGranted,
    DeniedPidMismatch,
    Retry,
    Failed,
};

// A bare PS5 title id: exactly 9 alphanumeric characters ("PPSA99203").
bool is_tid_shape(const char *s) {
    const size_t n = strlen(s);
    if (n != 9) return false;
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z'))) return false;
    }
    return true;
}

// Resolve the title id of a process: prefer the kernel-managed title id
// string exposed by the etaHEN fork (KProc::titleId()); fall back to scanning
// the SELF metadata path ("/mnt/sandbox/<TID>_<slot>/...") when the label is
// not set (some daemonized loaders leave it empty).
bool proc_tid(const KProc &proc, char *tid, size_t cap) {
    const String kernelTid = proc.titleId();
    const char *k = kernelTid.c_str();
    if (k[0] != '\0' && is_tid_shape(k)) {
        snprintf(tid, cap, "%s", k);
        return true;
    }
    const SelfInfo *info = proc.getSelfInfo();
    if (!info || info->path[0] == '\0') return false;
    const char *tok = info->path;
    while (tok != nullptr) {
        const char *next = strchr(tok, '/');
        const size_t len = next ? static_cast<size_t>(next - tok) : strlen(tok);
        if (len > 1 && len <= 15) {
            char token[16];
            memcpy(token, tok, len);
            token[len] = '\0';
            char tokenTid[12];
            if (valid_slot_name(token, tokenTid)) {
                snprintf(tid, cap, "%s", tokenTid);
                return true;
            }
        }
        tok = next ? next + 1 : nullptr;
    }
    return false;
}

// Make the resident process identifiable in process-list tools: the ELF
// loader (kstuff/etaHEN) spawns payloads under the generic name
// "payload.elf"; rewrite the kernel-managed process name right after boot.
void identify_self() {
    if (auto self = getProc()) {
        self->setName(kProcessName);
        log_line("process identity set: %s (pid=%d)", kProcessName, self->pid());
    } else {
        log_line("WARNING: could not rename own process from payload.elf");
    }
}

void write_pid_file() {
    int fd = open(kPidFile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    char buf[16];
    const int n = snprintf(buf, sizeof(buf), "%d\n", static_cast<int>(getpid()));
    (void)write(fd, buf, static_cast<size_t>(n));
    close(fd);
}

Result grant_app_jailbreak(const char *tid, int pid) {
    auto proc = getProc(pid);
    if (!proc || proc->pid() != pid) return Result::Retry;

    // Verify the PID actually lives in the sandbox named by the slot.
    char processTid[12];
    if (!proc_tid(*proc, processTid, sizeof(processTid)) ||
        strcmp(processTid, tid) != 0) {
        char selfPath[256];
        const SelfInfo *info = proc->getSelfInfo();
        snprintf(selfPath, sizeof(selfPath), "%s",
                 (info && info->path[0]) ? info->path : "<unavailable>");
        log_line("request rejected: slot TID=%s but PID %d self path is %s",
                 tid, pid, selfPath);
        return Result::DeniedPidMismatch;
    }

    auto cred = proc->ucred();
    if (!cred) return Result::Retry;
    if (cred->authid() == kAppJailbreakAuthId) return Result::AlreadyGranted;

    auto hijacker = Hijacker::getHijacker(pid);
    if (!hijacker) return Result::Retry;

    log_line("granting app-jailbreak profile: TID=%s PID=%d", tid, pid);
    hijacker->jailbreak(true);

    auto verifyProc = getProc(pid);
    if (!verifyProc || verifyProc->pid() != pid) return Result::Failed;
    auto verifyCred = verifyProc->ucred();
    if (!verifyCred || verifyCred->authid() != kAppJailbreakAuthId) return Result::Failed;
    return Result::Granted;
}

// Claim a marker atomically: rename it (same directory, so no EXDEV) to a
// private name competing consumers never look for. After a successful claim
// the canonical marker path no longer exists, so every other watcher of the
// legacy protocol is blind to this request.
enum class Claim { Ok, Gone, Failed };

Claim claim_marker(const char *canonical, bool alreadyClaimed, char *out, size_t cap) {
    if (alreadyClaimed) return Claim::Ok; // caller passes a claim path directly
    struct stat st{};
    if (stat(canonical, &st) != 0) return Claim::Gone;
    if (!S_ISREG(st.st_mode)) return Claim::Failed;
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", canonical);
    char *slash = strrchr(dir, '/');
    if (!slash) return Claim::Failed;
    *slash = '\0';
    const char *base = strrchr(canonical, '/');
    base = base ? base + 1 : canonical;
    if (snprintf(out, cap, "%s/%s%08x_%s", dir, kClaimPrefix, ++g_claimSeq, base) >=
        static_cast<int>(cap)) return Claim::Failed;
    if (rename(canonical, out) == 0) return Claim::Ok;
    if (errno == ENOENT) {
        // Someone else consumed the marker between stat and rename.
        log_line("lost race: %s vanished before claim", canonical);
        return Claim::Gone;
    }
    return Claim::Failed;
}

void process_marker_path(const char *slot, const char *tid, const char *path) {
    struct stat st{};
    if (stat(path, &st) != 0) {
        clear_retry(path);
        return;
    }
    if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
        static_cast<size_t>(st.st_size) > kMaxMarkerBytes) {
        log_line("discarding invalid marker: %s", path);
        unlink(path);
        clear_retry(path);
        write_status(slot, "INVALID_MARKER", -1);
        return;
    }

    char body[kMaxMarkerBytes + 1]{};
    if (read_marker(path, body, sizeof(body)) <= 0) return;
    const int pid = parse_pid(body);
    if (pid <= 1) {
        log_line("discarding malformed marker: %s", path);
        unlink(path);
        clear_retry(path);
        write_status(slot, "INVALID_PID", -1);
        return;
    }

    if (!is_allowed_title(tid)) {
        log_line("DENIED: TID=%s is not in allowlist (PID=%d)", tid, pid);
        unlink(path);
        clear_retry(path);
        write_status(slot, "DENIED_NOT_ALLOWLISTED", pid);
        return;
    }

    const Result result = grant_app_jailbreak(tid, pid);
    switch (result) {
        case Result::Granted:
            log_line("GRANTED: TID=%s PID=%d", tid, pid);
            unlink(path);
            clear_retry(path);
            write_status(slot, "GRANTED", pid);
            break;
        case Result::AlreadyGranted:
            // Idempotent acknowledgement: do not touch kernel credentials again.
            log_line("ALREADY_GRANTED: TID=%s PID=%d; duplicate request acknowledged", tid, pid);
            unlink(path);
            clear_retry(path);
            write_status(slot, "ALREADY_GRANTED", pid);
            break;
        case Result::DeniedPidMismatch:
            unlink(path);
            clear_retry(path);
            write_status(slot, "DENIED_PID_TID_MISMATCH", pid);
            break;
        case Result::Retry: {
            const unsigned attempts = retry_count(path);
            if (attempts >= kMaxDeferredAttempts) {
                log_line("STALE: unable to resolve TID=%s PID=%d after %u attempts",
                         tid, pid, attempts);
                unlink(path);
                clear_retry(path);
                write_status(slot, "STALE_OR_NOT_READY", pid);
            }
            // otherwise the claim file stays on disk and is retried next sweep
            break;
        }
        case Result::Failed:
            log_line("FAILED: verification after grant did not pass: TID=%s PID=%d", tid, pid);
            unlink(path);
            clear_retry(path);
            write_status(slot, "FAILED_VERIFY", pid);
            break;
    }
}

// Process every claim file currently resting in this sandbox's download0.
// Claims produced by this sweep and claims orphaned by a crash take the same
// path, so nothing is ever stranded.
void process_claims(const char *slot, const char *tid) {
    char dir[512];
    if (snprintf(dir, sizeof(dir), "%s/%s/download0", kSandboxRoot, slot) >=
        static_cast<int>(sizeof(dir))) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *entry;
    unsigned processed = 0;
    while ((entry = readdir(d)) != nullptr && processed < kMaxClaimsPerSweep) {
        const char *name = entry->d_name;
        if (strncmp(name, kClaimPrefix, strlen(kClaimPrefix)) != 0) continue;
        char path[512];
        if (snprintf(path, sizeof(path), "%s/%s", dir, name) >=
            static_cast<int>(sizeof(path))) continue;
        process_marker_path(slot, tid, path);
        ++processed;
    }
    closedir(d);
}

void scan_sandboxes() {
    DIR *dir = opendir(kSandboxRoot);
    if (!dir) return;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        char tid[12]{};
        if (!valid_slot_name(entry->d_name, tid)) continue;
        for (const char *marker : kMarkerNames) {
            char canonical[512];
            if (snprintf(canonical, sizeof(canonical), "%s/%s/download0/%s",
                         kSandboxRoot, entry->d_name, marker) >=
                static_cast<int>(sizeof(canonical))) continue;
            struct stat st{};
            if (stat(canonical, &st) != 0 || !S_ISREG(st.st_mode)) continue;
            if (static_cast<size_t>(st.st_size) > kMaxMarkerBytes) {
                log_line("discarding oversized marker: %s", canonical);
                unlink(canonical);
                write_status(entry->d_name, "INVALID_MARKER", -1);
                continue;
            }
            char claim[512];
            const Claim c = claim_marker(canonical, false, claim, sizeof(claim));
            if (c == Claim::Ok) {
                // The claim is picked up (and retried if needed) by
                // process_claims() in this same sweep.
                continue;
            }
            if (c == Claim::Failed) {
                // Same-directory rename only fails on real trouble; fall back
                // to processing the canonical path in place (old behaviour).
                process_marker_path(entry->d_name, tid, canonical);
            }
            // Claim::Gone: another consumer took it; already logged.
        }
        process_claims(entry->d_name, tid);
    }
    closedir(dir);
}

// --- kqueue wake-up layer -------------------------------------------------

void disable_kqueue(const char *why) {
    if (g_kq >= 0) {
        log_line("kqueue disabled (%s errno=%d); falling back to %u us poll",
                 why, errno, kPollIntervalUs);
        for (auto &w : g_watches) {
            if (w.fd >= 0) close(w.fd);
            w.fd = -1;
        }
        close(g_kq);
        g_kq = -1;
    }
}

void watch_refresh() {
    if (g_kq < 0) return;
    DIR *dir = opendir(kSandboxRoot);
    if (!dir) return;
    struct dirent *entry;
    struct kevent changes[kMaxWatches];
    int nchanges = 0;
    while ((entry = readdir(dir)) != nullptr) {
        char tid[12]{};
        if (!valid_slot_name(entry->d_name, tid)) continue;

        bool watched = false;
        for (auto &w : g_watches) {
            if (w.fd >= 0 && strcmp(w.slot, entry->d_name) == 0) {
                watched = true;
                break;
            }
        }
        if (watched) continue;

        int freeIdx = -1;
        for (int i = 0; i < kMaxWatches; ++i) {
            if (g_watches[i].fd < 0) { freeIdx = i; break; }
        }
        if (freeIdx < 0) break;

        char dpath[512];
        if (snprintf(dpath, sizeof(dpath), "%s/%s/download0",
                     kSandboxRoot, entry->d_name) >=
            static_cast<int>(sizeof(dpath))) continue;
        const int fd = open(dpath, O_RDONLY);
        if (fd < 0) continue; // download0 may not exist yet; retried next sweep
        WatchEntry &w = g_watches[freeIdx];
        w.fd = fd;
        snprintf(w.slot, sizeof(w.slot), "%s", entry->d_name);
        EV_SET(&changes[nchanges], static_cast<uintptr_t>(fd), EVFILT_VNODE,
               EV_ADD | EV_CLEAR,
               NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME, 0, &w);
        ++nchanges;
    }
    closedir(dir);
    if (nchanges > 0) {
        if (kevent(g_kq, changes, nchanges, nullptr, 0, nullptr) < 0) {
            disable_kqueue("register");
        }
    }
}

// Reap watches whose directory went away (sandbox exited).
void watch_reap(const struct kevent &ev) {
    auto *w = static_cast<WatchEntry *>(ev.udata);
    if (!w) return;
    if (ev.flags & EV_ERROR) return;
    if (ev.fflags & (NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE)) {
        close(w->fd);
        w->fd = -1;
        w->slot[0] = '\0';
    }
}

// --- policy audit ----------------------------------------------------------

// Every few seconds, surface processes running with the app-jailbreak authid
// whose title is not allowlisted. That is the only observable footprint a
// competing consumer leaves when it wins a race.
void policy_audit() {
    char tid[12];
    unsigned visited = 0;
    for (auto p : getAllProcs()) {
        if (!p) break;
        if (++visited > 4096) break; // defensive: corrupt or looping list
        auto cred = p->ucred();
        if (cred && cred->authid() == kAppJailbreakAuthId &&
            proc_tid(*p, tid, sizeof(tid)) && !is_allowed_title(tid)) {
            log_line("AUDIT: TID=%s PID=%d runs with app-jailbreak authid but is "
                     "not allowlisted (another consumer acted?)", tid, p->pid());
        }
    }
}

} // namespace

int main() {
    log_line("PS5 Permission Broker %s starting", kVersion);
    payload_args_t *args = payload_get_args();
    if (!args || args->kdata_base_addr == 0) {
        log_line("FATAL: payload args/kernel base unavailable; load through a supported ELF loader");
        return 1;
    }
    kernel_base = args->kdata_base_addr;
    log_line("kernel_base=0x%llx", static_cast<unsigned long long>(kernel_base));
    identify_self();

    if (!ensure_state_dir()) return 1;
    if (!create_default_allowlist()) {
        log_line("FATAL: could not create default allowlist");
        return 1;
    }
    if (!acquire_single_instance()) return 0;
    write_pid_file();

    // Optional mechanisms stay OFF unless explicitly enabled: kqueue attaches
    // kernel knotes to vnodes owned by other processes (unproven on all FWs),
    // and the audit reads kernel strings at fork-assumed offsets.
    const bool useKqueue = config_flag(kFlagKqueue);
    const bool useAudit = config_flag(kFlagAudit);

    if (useKqueue) {
        g_kq = kqueue();
    }
    log_line("exclusive authority acquired; watching %s (%s%u us poll%s)",
             kSandboxRoot,
             g_kq >= 0 ? "kqueue + " : "poll, ",
             kPollIntervalUs,
             useAudit ? ", audit on" : ", audit off");
    if (useKqueue && g_kq < 0) {
        log_line("kqueue() failed errno=%d; poll-only mode", errno);
    }
    log_line("protocol: etahen_jailbreak + onionhen_jailbreak; allowlist=%s", kAllowlist);
    log_line("claims are atomic (rename); duplicate grants return ALREADY_GRANTED");

    timespec pollTimeout{};
    pollTimeout.tv_nsec = static_cast<long>(kPollIntervalUs) * 1000L;

    for (;;) {
        // Whether this iteration already slept (kevent timeout / usleep).
        bool slept = false;
        if (g_kq >= 0) {
            struct kevent ev;
            const int n = kevent(g_kq, nullptr, 0, &ev, 1, &pollTimeout);
            if (n < 0) {
                disable_kqueue("wait");
            } else if (n == 0) {
                slept = true; // timed out: the wait was the throttle
            } else {
                watch_reap(ev);
            }
        } else {
            usleep(kPollIntervalUs);
            slept = true;
        }

        scan_sandboxes();
        watch_refresh();

        // Hard throttle: while apps boot, VNODE events fire constantly and
        // kevent returns instantly; without this the loop spins at full
        // speed and the audit fires far earlier than intended.
        if (!slept) {
            usleep(kPollIntervalUs);
        }

        ++g_loops;
        if (useAudit && g_loops % kAuditEveryLoops == 0) {
            policy_audit();
        }
    }
    return 0;
}
