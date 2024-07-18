module HellsGate.HellsGate;

import core.sys.windows.windows;
import core.stdcpp.vector;
import std.stdio;


extern (C) int strncmp ( const char * str1, const char * str2, size_t num );

T rvaToVa(T) (DWORD_PTR peBase, DWORD offset) {
    return cast(T)(peBase + offset);
}

PVOID getImage(string targetMod) {
    return cast(PVOID)GetModuleHandleA(cast(LPCSTR)targetMod);
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

        if (*cast(PBYTE)(pAddress + cw) == 0x0f && *cast(PBYTE)(pAddress + cw + 1) == 0x05) {
            return 0;
        }

        if (*cast(PBYTE)(pAddress + cw) == 0xc3) {
            return 0;
        }
        /* 
        System Call Stub:

         mov r10, rcx
         mov eax, <SSN> 

         */
        if (*cast(PBYTE)(pAddress + cw) == 0x4c && *cast(PBYTE)(pAddress + cw + 1) == 0x8b && *cast(PBYTE)(pAddress + cw + 2) == 0xd1 && *cast(PBYTE)(pAddress + cw + 6) == 0x00 && *cast(PBYTE)(pAddress + cw + 7) == 0x00) {

            BYTE high = *cast(PBYTE)(pAddress + 5 + cw);
            BYTE low = *cast(PBYTE)(pAddress + 4 + cw);

            WORD ssn = (high << 8) | low;
            return ssn;

        }

        cw++;
    }

}

void main() {

    auto peImage = getImage("NTDLL");
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

        if (!strncmp(fnName, "Nt", 2)) {
            // utilize the getFunctionSsn for a full implemenation of hell's gate, I won't spoon feed you.
            writefln("%s - 0x%x", printableName, getFunctionSsn(fnAddr));
        }
    }
    

}