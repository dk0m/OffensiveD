module ModuleEnumeration.EnumProcessModules;

import core.sys.windows.windows;
import core.sys.windows.psapi;
import core.stdcpp.vector;
import std.stdio;

pragma(lib, "psapi.lib");


vector!HMODULE getProcessModules(HANDLE hProcess) {

    auto modules = vector!HMODULE(Default);

    HMODULE[1024] mainModules;
    DWORD neededSize;
        
    EnumProcessModules(hProcess, &mainModules[0], mainModules.sizeof, &neededSize);

    SIZE_T amountOfMods = neededSize / HMODULE.sizeof;

    for (SIZE_T i = 0; i < amountOfMods; i++) {
        modules.push_back(mainModules[i]);
    }

    return modules;
}

MODULEINFO getModuleInfo(HANDLE hProcess, HMODULE hModule) {
    MODULEINFO modInfo;

    GetModuleInformation(hProcess, hModule, &modInfo, MODULEINFO.sizeof);

    return modInfo;
}

CHAR[MAX_PATH] getModuleName(HANDLE hProcess, HMODULE hModule) {
    CHAR[MAX_PATH] modName;

    GetModuleBaseNameA(hProcess, hModule, &modName[0], modName.sizeof);

    return modName;
}
