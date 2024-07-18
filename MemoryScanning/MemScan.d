module MemoryScanning.MemScan;

import core.sys.windows.windows;
import core.sys.windows.psapi;
import core.stdcpp.vector;
import std.stdio;



vector!MEMORY_BASIC_INFORMATION getProcessMemoryRegions(HANDLE hProcess) {
    auto memRegions = vector!MEMORY_BASIC_INFORMATION(Default);

    MEMORY_BASIC_INFORMATION mbi;
    PVOID baseAddr;

    while (VirtualQueryEx(hProcess, baseAddr, &mbi, mbi.sizeof) != 0) {
        memRegions.push_back(mbi);
        baseAddr = cast(PVOID) (mbi.BaseAddress + mbi.RegionSize);
    }

    return memRegions;
}
