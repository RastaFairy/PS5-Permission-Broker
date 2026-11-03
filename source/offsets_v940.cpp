/*
 * Multi-firmware kernel offset resolver.
 *
 * Resolution strategy (maximum firmware coverage):
 *
 *   1) Preferred path: PS5 Payload SDK runtime symbols (KERNEL_ADDRESS_*),
 *      resolved per-FW by kstuff's symbol tables when the payload is loaded.
 *      Works on every firmware kstuff supports, with no hardcoded values.
 *
 *   2) Fallback path: consolidated public per-FW offset table selected via
 *      sysctl("kern.sdk_version"). Sources, cross-checked where they overlap:
 *        - etaHEN consolidated libhijacker table (FW 1.00 -> 10.60)
 *        - kstuff prosper0gdb offsets.c (FW 3.00 -> 4.51, agrees with etaHEN
 *          on allproc/security_flags; its qa/utoken values are used because
 *          etaHEN's pre-6.00 qa/utoken entries are stale copies of the 1.00
 *          values)
 *        - astrelsky/libhijacker vanilla offsets.cpp (rootvnode 3.00 -> 4.51)
 *
 * Only allproc and root_vnode are load-bearing for this broker (process walk
 * + sandbox escape). security/qa/utoken are exposed for API completeness;
 * stale values there cannot affect the grant path.
 *
 * The KERNEL_ADDRESS_* externs are declared weak: if the running loader has
 * no symbol table entry for them, they read as 0 and we fall back to the
 * table instead of failing to load.
 */
extern "C" {
#include <stdint.h>
#include <sys/types.h>
#include <sys/sysctl.h>

extern const intptr_t KERNEL_ADDRESS_DATA_BASE __attribute__((weak));
extern const intptr_t KERNEL_ADDRESS_ALLPROC __attribute__((weak));
extern const intptr_t KERNEL_ADDRESS_SECURITY_FLAGS __attribute__((weak));
extern const intptr_t KERNEL_ADDRESS_QA_FLAGS __attribute__((weak));
extern const intptr_t KERNEL_ADDRESS_UTOKEN_FLAGS __attribute__((weak));
extern const intptr_t KERNEL_ADDRESS_ROOTVNODE __attribute__((weak));
}

namespace offsets {

struct FwEntry {
    uint32_t version;      // kern.sdk_version & 0xffff0000
    size_t allproc;
    size_t security_flags;
    size_t qa_flags;
    size_t utoken_flags;
    size_t root_vnode;
};

// clang-format off
static const FwEntry kFwTable[] = {
    // FW 1.00 - 1.14 (etaHEN)
    {0x1000000, 0x26D1C18, 0x6241074, 0x6241098, 0x6646710, 0x6565540},
    // FW 2.00 - 2.70 (etaHEN)
    {0x2000000, 0x2701C28, 0x63E1274, 0x6241098, 0x6646710, 0x67134C0},
    // FW 3.00/3.10/3.20/3.21 (etaHEN + kstuff + astrelsky, all agree)
    {0x3000000, 0x276DC58, 0x6466474, 0x6466498, 0x6466500, 0x67AB4C0},
    // FW 4.00 (etaHEN allproc/root; kstuff flags)
    {0x4000000, 0x27EDCB8, 0x6506474, 0x6506498, 0x6506500, 0x66E74C0},
    // FW 4.02 (kstuff flags; astrelsky rootvnode)
    {0x4020000, 0x27EDCB8, 0x6505474, 0x6505498, 0x6505500, 0x66E64C0},
    // FW 4.03/4.50/4.51 (etaHEN + kstuff + astrelsky)
    {0x4030000, 0x27EDCB8, 0x6506474, 0x6506498, 0x6506500, 0x66E74C0},
    {0x4500000, 0x27EDCB8, 0x6506474, 0x6506498, 0x6506500, 0x66E74C0},
    {0x4510000, 0x27EDCB8, 0x6506474, 0x6506498, 0x6506500, 0x66E74C0},
    // FW 5.00/5.02/5.10/5.50 (etaHEN) - target baseline of this broker
    {0x5000000, 0x291DD00, 0x66466EC, 0x6646710, 0x6646778, 0x6853510},
    // FW 6.00/6.02/6.50 (etaHEN)
    {0x6000000, 0x2869D20, 0x65968EC, 0x6596910, 0x6596978, 0x679F510},
    // FW 7.00/7.01/7.20/7.40/7.60/7.61 (etaHEN)
    {0x7000000, 0x2859D50, 0x0AC8064, 0x0AC8088, 0x0AC80F0, 0x30C7510},
    // FW 8.00/8.20/8.40/8.60 (etaHEN)
    {0x8000000, 0x2875D50, 0x0AC3064, 0x0AC3088, 0x0AC30F0, 0x30FB510},
    // FW 9.00 (etaHEN)
    {0x9000000, 0x2755D50, 0x0D72064, 0x0D72088, 0x0D720F0, 0x2FDB510},
    // FW 9.05/9.20/9.40/9.60 (etaHEN)
    {0x9050000, 0x2755D50, 0x0D73064, 0x0D73088, 0x0D730F0, 0x2FDB510},
    // FW 10.00/10.01/10.20/10.40/10.60 (etaHEN)
    {0x10000000, 0x2765D70, 0x0D79064, 0x0D79088, 0x0D790F0, 0x2FA3510},
};
// clang-format on

static uint32_t system_sw_version() {
    static uint32_t cached;
    if (cached != 0) return cached;
    size_t size = sizeof(cached);
    if (sysctlbyname("kern.sdk_version", &cached, &size, nullptr, 0) != 0) {
        return 0;
    }
    return cached;
}

static const FwEntry *table_entry() {
    static const FwEntry *cached = reinterpret_cast<const FwEntry *>(1);
    if (cached == reinterpret_cast<const FwEntry *>(1)) {
        cached = nullptr;
        const uint32_t major = system_sw_version() & 0xffff0000;
        for (const FwEntry &e : kFwTable) {
            if (e.version == major) {
                cached = &e;
                break;
            }
        }
    }
    return cached;
}

// Convert an absolute kernel VA resolved at runtime by kstuff into an offset
// relative to the kernel data base.
static size_t rel(intptr_t absolute_va) {
    return static_cast<size_t>(absolute_va - KERNEL_ADDRESS_DATA_BASE);
}

size_t allproc() {
    if (KERNEL_ADDRESS_ALLPROC && KERNEL_ADDRESS_DATA_BASE) {
        return rel(KERNEL_ADDRESS_ALLPROC);
    }
    const FwEntry *e = table_entry();
    return e ? e->allproc : static_cast<size_t>(-1);
}

size_t security_flags() {
    if (KERNEL_ADDRESS_SECURITY_FLAGS && KERNEL_ADDRESS_DATA_BASE) {
        return rel(KERNEL_ADDRESS_SECURITY_FLAGS);
    }
    const FwEntry *e = table_entry();
    return e ? e->security_flags : static_cast<size_t>(-1);
}

size_t qa_flags() {
    if (KERNEL_ADDRESS_QA_FLAGS && KERNEL_ADDRESS_DATA_BASE) {
        return rel(KERNEL_ADDRESS_QA_FLAGS);
    }
    const FwEntry *e = table_entry();
    return e ? e->qa_flags : static_cast<size_t>(-1);
}

size_t utoken_flags() {
    if (KERNEL_ADDRESS_UTOKEN_FLAGS && KERNEL_ADDRESS_DATA_BASE) {
        return rel(KERNEL_ADDRESS_UTOKEN_FLAGS);
    }
    const FwEntry *e = table_entry();
    return e ? e->utoken_flags : static_cast<size_t>(-1);
}

size_t root_vnode() {
    if (KERNEL_ADDRESS_ROOTVNODE && KERNEL_ADDRESS_DATA_BASE) {
        return rel(KERNEL_ADDRESS_ROOTVNODE);
    }
    const FwEntry *e = table_entry();
    return e ? e->root_vnode : static_cast<size_t>(-1);
}

} // namespace offsets
