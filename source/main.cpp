/*
 * PS5 Permission Broker - FW 5.50 baseline
 *
 * One resident consumer for the legacy etaHEN/OnionHEN app-jailbreak marker.
 * This deliberately does NOT install global kernel hooks and cannot stop an
 * unrelated binary from writing credentials directly. Competing marker
 * consumers must be removed/disabled as documented in README.md.
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
constexpr const char *kVersion = "0.1.0-fw550";
constexpr const char *kSandboxRoot = "/mnt/sandbox";
constexpr const char *kStateDir = "/data/permission-broker";
constexpr const char *kAllowlist = "/data/permission-broker/allowlist.txt";
constexpr const char *kLockFile = "/data/permission-broker/authority.lock";
constexpr const char *kLogFile = "/data/permission-broker/broker.log";
constexpr uint64_t kAppJailbreakAuthId = 0x4801000000000013ull;
constexpr unsigned kPollIntervalUs = 250000;
constexpr unsigned kMaxDeferredAttempts = 40; // 10 s at 250 ms
constexpr size_t kMaxMarkerBytes = 1024;

const char *kMarkerNames[] = {
    "etahen_jailbreak",
    "onionhen_jailbreak",
};

int g_lockFd = -1;

struct RetryEntry {
    char path[512];
    unsigned attempts;
};
RetryEntry g_retries[64]{};

void log_line(const char *fmt, ...) {
    char msg[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    klog_printf("[perm-broker] %s\n", msg);

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
            if (entry.attempts < 100000) ++entry.attempts;
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

Result grant_app_jailbreak(const char *tid, int pid) {
    auto proc = getProc(pid);
    if (!proc || proc->pid() != pid) return Result::Retry;

    // Verify the PID actually lives in the sandbox named by the slot.
    // libhijacker exposes the loaded SELF metadata per process; app SELF
    // paths are rooted at /mnt/sandbox/<TITLE_ID>_<slot>/.
    const SelfInfo *info = proc->getSelfInfo();
    if (!info || info->path[0] == '\0') return Result::Retry;
    bool tidMatches = false;
    char prefix[64];
    if (snprintf(prefix, sizeof(prefix), "/mnt/sandbox/%s/", tid) <
        static_cast<int>(sizeof(prefix)) && strstr(info->path, prefix)) {
        tidMatches = true;
    } else {
        // Fallback: first SELF path token shaped like <TID>_<slot>.
        const char *tok = info->path;
        while (tok != nullptr && !tidMatches) {
            const char *next = strchr(tok, '/');
            const size_t len = next ? static_cast<size_t>(next - tok) : strlen(tok);
            if (len > 1 && len <= 15) {
                char token[16];
                memcpy(token, tok, len);
                token[len] = '\0';
                char tokenTid[12];
                if (valid_slot_name(token, tokenTid) && strcmp(tokenTid, tid) == 0) {
                    tidMatches = true;
                }
            }
            tok = next ? next + 1 : nullptr;
        }
    }
    if (!tidMatches) {
        log_line("request rejected: slot TID=%s but PID %d self path is %s",
                 tid, pid, info->path);
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

void process_marker(const char *slot, const char *tid, const char *markerName) {
    char path[512];
    const int pathLen = snprintf(path, sizeof(path), "%s/%s/download0/%s",
                                 kSandboxRoot, slot, markerName);
    if (pathLen <= 0 || pathLen >= static_cast<int>(sizeof(path))) return;

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

void scan_sandboxes() {
    DIR *dir = opendir(kSandboxRoot);
    if (!dir) return;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        char tid[12]{};
        if (!valid_slot_name(entry->d_name, tid)) continue;
        for (const char *marker : kMarkerNames) {
            process_marker(entry->d_name, tid, marker);
        }
    }
    closedir(dir);
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

    if (!ensure_state_dir()) return 1;
    if (!create_default_allowlist()) {
        log_line("FATAL: could not create default allowlist");
        return 1;
    }
    if (!acquire_single_instance()) return 0;

    log_line("exclusive authority acquired; watching %s", kSandboxRoot);
    log_line("protocol: etahen_jailbreak + onionhen_jailbreak; allowlist=%s", kAllowlist);
    log_line("duplicate grants return ALREADY_GRANTED and do not rewrite credentials");

    for (;;) {
        scan_sandboxes();
        usleep(kPollIntervalUs);
    }
    return 0;
}
