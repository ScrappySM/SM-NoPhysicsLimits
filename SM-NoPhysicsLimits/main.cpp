// patch.cpp - Scrap Mechanic (sm_legacy) physics limits remover
// Inject as a DLL. Both host and all clients must use the same limit values.
//
// Patches applied:
//   1. dword_140FF7CA0  1000.0f -> NEW_VELOCITY_LIMIT  (lin + ang vel encoding range)
//   2. dword_140FF7CC8  4000.0f -> NEW_POSITION_LIMIT  (position encoding range)
//   3. 0x1402D843C      NOPs the hard minss clamp on velocity magnitude
//
// NOTE: Increasing the encoding range reduces quantization precision proportionally.
//       A 64x velocity increase means ~64x coarser velocity resolution over the wire.
//       Tune to the smallest values that satisfy your use case.

#include <Windows.h>
#include <cstdint>
#include <cstring>

// Tunable limits
static constexpr float NEW_VELOCITY_LIMIT = 65536.0f;  // was 1000.0f
static constexpr float NEW_POSITION_LIMIT = 262144.0f; // was 4000.0f

// RVAs from IDA base 0x140000000
static constexpr uintptr_t RVA_VELOCITY_FLOAT = 0x00FF7CA0; // dword_140FF7CA0
static constexpr uintptr_t RVA_POSITION_FLOAT = 0x00FF7CC8; // dword_140FF7CC8
static constexpr uintptr_t RVA_MINSS_CLAMP = 0x002D843C;    // minss xmm6,[dword_140FF7CA0]
static constexpr size_t MINSS_CLAMP_SIZE = 8;

// Expected current bytes at each site - guards against patching a different build.
static constexpr uint8_t EXPECTED_VELOCITY_BYTES[4] = {0x00, 0x00, 0x7A, 0x44}; // 1000.0f LE
static constexpr uint8_t EXPECTED_POSITION_BYTES[4] = {0x00, 0x00, 0x7A, 0x45}; // 4000.0f LE
static constexpr uint8_t EXPECTED_MINSS_BYTES[8] = {0xF3, 0x0F, 0x5D, 0x35,
                                                    0x5C, 0xF8, 0xD1, 0x00};

static bool PatchBytes(void *addr, const void *newBytes, size_t size)
{
    DWORD oldProt = 0;
    if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProt))
        return false;
    memcpy(addr, newBytes, size);
    VirtualProtect(addr, size, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), addr, size);
    return true;
}

static bool VerifyBytes(const void *addr, const uint8_t *expected, size_t size)
{
    return memcmp(addr, expected, size) == 0;
}

static void ApplyPatches()
{
    const uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);

    void *pVelFloat = reinterpret_cast<void *>(base + RVA_VELOCITY_FLOAT);
    void *pPosFloat = reinterpret_cast<void *>(base + RVA_POSITION_FLOAT);
    void *pMinss = reinterpret_cast<void *>(base + RVA_MINSS_CLAMP);

    // Patch 1: velocity encoding range
    if (!VerifyBytes(pVelFloat, EXPECTED_VELOCITY_BYTES, sizeof(EXPECTED_VELOCITY_BYTES)))
    {
        OutputDebugStringA("[patch] SKIP velocity float: unexpected bytes (wrong build?)\n");
    }
    else
    {
        float v = NEW_VELOCITY_LIMIT;
        if (PatchBytes(pVelFloat, &v, sizeof(v)))
            OutputDebugStringA("[patch] OK   velocity limit: 1000 -> NEW_VELOCITY_LIMIT\n");
        else
            OutputDebugStringA("[patch] FAIL velocity float: VirtualProtect error\n");
    }

    // Patch 2: position encoding range
    if (!VerifyBytes(pPosFloat, EXPECTED_POSITION_BYTES, sizeof(EXPECTED_POSITION_BYTES)))
    {
        OutputDebugStringA("[patch] SKIP position float: unexpected bytes (wrong build?)\n");
    }
    else
    {
        float p = NEW_POSITION_LIMIT;
        if (PatchBytes(pPosFloat, &p, sizeof(p)))
            OutputDebugStringA("[patch] OK   position limit: 4000 -> NEW_POSITION_LIMIT\n");
        else
            OutputDebugStringA("[patch] FAIL position float: VirtualProtect error\n");
    }

    // Patch 3: NOP the hard minss clamp on velocity magnitude
    if (!VerifyBytes(pMinss, EXPECTED_MINSS_BYTES, MINSS_CLAMP_SIZE))
    {
        OutputDebugStringA("[patch] SKIP minss clamp: unexpected bytes (wrong build?)\n");
    }
    else
    {
        uint8_t nops[MINSS_CLAMP_SIZE];
        memset(nops, 0x90, sizeof(nops));
        if (PatchBytes(pMinss, nops, sizeof(nops)))
            OutputDebugStringA("[patch] OK   minss clamp NOP'd at 0x1402D843C\n");
        else
            OutputDebugStringA("[patch] FAIL minss clamp: VirtualProtect error\n");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        ApplyPatches();
    }
    return TRUE;
}
