// patch.cpp - Scrap Mechanic (sm_legacy) physics limits remover
// Inject as a DLL. Both host and all clients must use the same limit values.
//
// Patches applied:
//   1. dword_140FF7CA0           1000.0f  -> NEW_VELOCITY_LIMIT  (.rdata, RIP-relative refs)
//   2. dword_140FF7CC8           4000.0f  -> NEW_POSITION_LIMIT  (.rdata, RIP-relative refs)
//   3. 0x1402D843C               NOPs the hard minss velocity magnitude clamp (8 bytes)
//   4. sub_140342BD0 imm @ +0x153  -500.0f  -> -NEW_VELOCITY_LIMIT  (inline range MIN)
//   5. sub_140342BD0 imm @ +0x16F  1000.0f  -> NEW_VELOCITY_LIMIT   (inline range MAX)
//   6. sub_14073A090 imm @ +0x03C  1000.0f  -> NEW_VELOCITY_LIMIT   (ctor field +8)
//   7. sub_140783C3A imm @ +0x006  4000.0f  -> NEW_POSITION_LIMIT   (inline pos range)
//
// NOTE: Increasing the encoding range reduces quantization precision proportionally.
//       Tune to the smallest values that satisfy your use case.
//       Both host and all clients MUST use identical values.

#include <Windows.h>
#include <cstdint>
#include <cstring>

// Tunable limits
static constexpr float NEW_VELOCITY_LIMIT = 65536.0f;   // was 1000.0f
static constexpr float NEW_POSITION_LIMIT = 262144.0f;  // was 4000.0f

// RVAs of the 4-byte float values to overwrite (relative to exe base = IDA base - 0x140000000)
struct PatchSite {
    uintptr_t    rva;
    uint8_t      expected[4]; // guard bytes - skip if mismatched (wrong build)
    float        newValue;
    const char*  label;
};

static const PatchSite k_patches[] = {
    // .rdata shared constants (RIP-relative, affect all encode/decode paths)
    { 0x00FF7CA0, {0x00,0x00,0x7A,0x44},  0.0f,            "[patch] OK   .rdata vel float:    1000 -> NEW_VELOCITY_LIMIT\n"  },
    { 0x00FF7CC8, {0x00,0x00,0x7A,0x45},  0.0f,            "[patch] OK   .rdata pos float:    4000 -> NEW_POSITION_LIMIT\n"  },

    // Inline immediates in code (mov dword ptr [reg+off], imm32)
    // sub_140342BD0: velocity range struct MIN field  (-500.0f -> -NEW_VELOCITY_LIMIT)
    { 0x00342F53, {0x00,0x00,0xFA,0xC3},  0.0f,            "[patch] OK   inline vel MIN:      -500 -> -NEW_VELOCITY_LIMIT\n" },
    // sub_140342BD0: velocity range struct MAX field  (1000.0f -> NEW_VELOCITY_LIMIT)
    { 0x00342F6F, {0x00,0x00,0x7A,0x44},  0.0f,            "[patch] OK   inline vel MAX:      1000 -> NEW_VELOCITY_LIMIT\n"  },
    // sub_14073A090: constructor field +8             (1000.0f -> NEW_VELOCITY_LIMIT)
    { 0x0073A0CC, {0x00,0x00,0x7A,0x44},  0.0f,            "[patch] OK   inline vel ctor:     1000 -> NEW_VELOCITY_LIMIT\n"  },
    // sub_140783C3A: position range field [rsi+0x110] (4000.0f -> NEW_POSITION_LIMIT)
    { 0x00783C40, {0x00,0x00,0x7A,0x45},  0.0f,            "[patch] OK   inline pos range:    4000 -> NEW_POSITION_LIMIT\n"  },
};

static const uintptr_t RVA_MINSS_CLAMP  = 0x002D843C;
static const uint8_t   EXPECTED_MINSS[] = {0xF3,0x0F,0x5D,0x35,0x5C,0xF8,0xD1,0x00};

static bool PatchBytes(void* addr, const void* src, size_t size)
{
    DWORD old = 0;
    if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old))
        return false;
    memcpy(addr, src, size);
    VirtualProtect(addr, size, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, size);
    return true;
}

static void ApplyPatches()
{
    const uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);

    // Float value patches
    for (auto& p : k_patches) {
        void* addr = reinterpret_cast<void*>(base + p.rva);

        if (memcmp(addr, p.expected, 4) != 0) {
            OutputDebugStringA("[patch] SKIP (unexpected bytes - wrong build?)\n");
            continue;
        }

        // Pick the right value based on which site this is
        float val;
        bool isNeg    = (p.expected[3] & 0x80) != 0; // sign bit set = negative value
        bool isPos    = (p.expected[2] == 0x7A && p.expected[3] == 0x45); // 4000.0f
        if (isNeg)
            val = -NEW_VELOCITY_LIMIT;
        else if (isPos)
            val = NEW_POSITION_LIMIT;
        else
            val = NEW_VELOCITY_LIMIT;

        if (PatchBytes(addr, &val, 4))
            OutputDebugStringA(p.label);
        else
            OutputDebugStringA("[patch] FAIL VirtualProtect\n");
    }

    // minss magnitude clamp NOP (8 bytes in .text)
    void* pMinss = reinterpret_cast<void*>(base + RVA_MINSS_CLAMP);
    if (memcmp(pMinss, EXPECTED_MINSS, sizeof(EXPECTED_MINSS)) != 0) {
        OutputDebugStringA("[patch] SKIP minss clamp: unexpected bytes\n");
    } else {
        uint8_t nops[8]; memset(nops, 0x90, 8);
        if (PatchBytes(pMinss, nops, 8))
            OutputDebugStringA("[patch] OK   minss clamp NOP'd (0x1402D843C, 8 bytes)\n");
        else
            OutputDebugStringA("[patch] FAIL minss NOP: VirtualProtect error\n");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        ApplyPatches();
    }
    return TRUE;
}
