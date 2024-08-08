#include "Hooks.hpp"

DWORD WINAPI MainThread(LPVOID lp)  {
    AllocConsole();
    FILE* file;
    freopen_s(&file, "CONOUT$", "w", stdout);

    printf("\nError Addy: %llx\n", Patterns::Error);
    printf("Modify Addy: %llx\n", Patterns::Modify);
    printf("Req Addy: %llx\n", Patterns::Req);

    Hooks::Start();

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(MainThread), nullptr, 0, nullptr);
    }

    return TRUE;
}
