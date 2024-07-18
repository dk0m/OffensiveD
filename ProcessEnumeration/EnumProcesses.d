module ProcessEnumeration.EnumProcesses;

import core.sys.windows.windows;
import core.sys.windows.psapi;
import std.stdio;


pragma(lib, "psapi.lib");

DWORD getProcessId(string targetProcName) {
    DWORD[1024] procIds;
    DWORD bytesNeeded;

    EnumProcesses(&procIds[0], procIds.sizeof, &bytesNeeded);

    SIZE_T amountOfPids = bytesNeeded / DWORD.sizeof;

    for (SIZE_T i = 0 ; i < amountOfPids ; i++) {
        
        DWORD procId = procIds[i];
        HANDLE currProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procId);

        HMODULE mainModule;
        DWORD neededSize;
        
        EnumProcessModules(currProc, &mainModule, mainModule.sizeof, &neededSize);

        CHAR[MAX_PATH] processName;
        GetModuleBaseNameA(currProc, mainModule, &processName[0], processName.sizeof);

        CloseHandle(currProc);

        if (!lstrcmpiA(&processName[0], &targetProcName[0])) {
            return procId;
        }

    }

    return 0;
}
