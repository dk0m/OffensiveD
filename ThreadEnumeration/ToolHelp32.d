module ThreadEnumeration.ToolHelp32;

import core.sys.windows.windows;
import core.sys.windows.tlhelp32;
import std.stdio;

import core.stdcpp.vector;

vector!THREADENTRY32 getProcessThreads(DWORD procId) {
    
    auto threads = vector!THREADENTRY32(Default);

    THREADENTRY32 te32;
    te32.dwSize = THREADENTRY32.sizeof;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    while (Thread32Next(snapshot, &te32)) {
        auto ownerProcId = te32.th32OwnerProcessID;

        if (ownerProcId == procId) {
            threads.push_back(te32);
        }
    }

    return threads;
}
