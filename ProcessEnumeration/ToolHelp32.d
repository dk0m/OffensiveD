module ProcessEnumeration.ToolHelp32;

import core.sys.windows.windows;
import core.sys.windows.tlhelp32;
import std.stdio;


DWORD getProcessId(string targetProcName) {
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = PROCESSENTRY32.sizeof;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    while (Process32Next(snapshot, &pe32)) {
        auto procName = pe32.szExeFile;
        auto procId = pe32.th32ProcessID;

        if (!lstrcmpiW(&procName[0], &targetProcName[0])) {
            return procId;
        }
    }

    return 0;
}
