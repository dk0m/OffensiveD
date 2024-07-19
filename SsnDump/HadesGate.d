module HadesGate.HellsGate;

import core.sys.windows.windows;
import core.stdcpp.vector;
import std.stdio;


extern (C) int strncmp ( const char * str1, const char * str2, size_t num );

T rvaToVa(T) (DWORD_PTR peBase, DWORD offset) {
    return cast(T)(peBase + offset);
}

PVOID getImageL(string targetMod) {
    return cast(PVOID)LoadLibraryA(cast(LPCSTR)targetMod);
}

string lpcstrToStr(LPCSTR lpString) {
    string finalStr = "";

    DWORD cw = 0;

    while (true) {
        
        char currChar = *cast(char*)(lpString + cw);

        if (currChar == '\0') {
            break;
        }

        finalStr ~= currChar;

        cw++;
    }

    return finalStr;
}



WORD getFunctionSsn(PVOID fnAddress) {

    auto pAddress = cast(PBYTE)fnAddress;

    WORD cw = 0;
    while (TRUE) {

        // check for jmp, in this case we are done.
        if (*cast(PBYTE)(pAddress + cw) == 0xE9) {
            return 0;
        }

        // check for mov eax, XX_XX (XX_XX is SSN)

        if (*cast(PBYTE)(pAddress + cw) == 0xB8) {

            WORD ssn = *cast(PWORD)(pAddress + cw + 1); // XX_XX (the ssn)
            return ssn;
        }


        cw++;
    }

}

struct SystemCall {
    string Name;
    WORD Ssn;
}
vector!SystemCall getSystemCalls() {
    auto systemCalls = vector!SystemCall(Default);
    auto peImage = getImageL("ntoskrnl.exe");
    auto peBase = cast(DWORD_PTR)peImage;

    PIMAGE_DOS_HEADER dosHdr = cast(PIMAGE_DOS_HEADER)(peBase);
    
    PIMAGE_NT_HEADERS ntHdrs = rvaToVa!PIMAGE_NT_HEADERS(peBase, dosHdr.e_lfanew);

    IMAGE_OPTIONAL_HEADER optHdr = ntHdrs.OptionalHeader;
    IMAGE_FILE_HEADER fileHdr = ntHdrs.FileHeader;

    auto expDir = rvaToVa!PIMAGE_EXPORT_DIRECTORY(peBase, cast(DWORD)optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD addrOfNames = rvaToVa!PDWORD(peBase, expDir.AddressOfNames);
    PDWORD addrOfFuncs = rvaToVa!PDWORD(peBase, expDir.AddressOfFunctions);
    PWORD addrOfNameOrds = rvaToVa!PWORD(peBase, expDir.AddressOfNameOrdinals);

    for (SIZE_T i = 0; i < expDir.NumberOfFunctions - 1; i++) {
        LPCSTR fnName = rvaToVa!LPCSTR(peBase, addrOfNames[i]);
        WORD fnOrd = addrOfNameOrds[i];
        PVOID fnAddr = rvaToVa!PVOID(peBase, addrOfFuncs[fnOrd]);

        string printableName = lpcstrToStr(fnName);

        if (!strncmp(fnName, "Zw", 2)) {
            
            systemCalls.push_back(
                * new SystemCall(printableName, getFunctionSsn(fnAddr))
            );
            
        }
    }

    return systemCalls;

}
void main() {

    auto sysCalls = getSystemCalls();

    foreach(SystemCall syscall ; sysCalls) {
        writefln("%s - %d (0x%x)", syscall.Name, syscall.Ssn, syscall.Ssn);
    }
    
}