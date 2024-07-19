module SsnDump.ExceptionDirectory;

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

struct SystemCall {
    int Ssn;
    string Name;
    PVOID Address;
}

vector!SystemCall getSystemCalls() {
    auto peImage = getImage("NTDLL");
    auto peBase = cast(DWORD_PTR)peImage;

    PIMAGE_DOS_HEADER dosHdr = cast(PIMAGE_DOS_HEADER)(peBase);
    
    PIMAGE_NT_HEADERS ntHdrs = rvaToVa!PIMAGE_NT_HEADERS(peBase, dosHdr.e_lfanew);

    IMAGE_OPTIONAL_HEADER optHdr = ntHdrs.OptionalHeader;
    IMAGE_FILE_HEADER fileHdr = ntHdrs.FileHeader;

    auto expDir = rvaToVa!PIMAGE_EXPORT_DIRECTORY(peBase, cast(DWORD)optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PIMAGE_RUNTIME_FUNCTION_ENTRY exceptionDir = rvaToVa!PIMAGE_RUNTIME_FUNCTION_ENTRY(peBase, cast(DWORD)optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

    PDWORD addrOfNames = rvaToVa!PDWORD(peBase, expDir.AddressOfNames);
    PDWORD addrOfFuncs = rvaToVa!PDWORD(peBase, expDir.AddressOfFunctions);
    PWORD addrOfNameOrds = rvaToVa!PWORD(peBase, expDir.AddressOfNameOrdinals);

    int currentIndex = 0;
    int ssn = 0;

    vector!SystemCall systemCalls = vector!SystemCall(Default);

    while (exceptionDir[currentIndex].BeginAddress) {

        IMAGE_RUNTIME_FUNCTION_ENTRY rtfEntry = exceptionDir[currentIndex];
        DWORD beginAddr = rtfEntry.BeginAddress;

        for (SIZE_T i = 0; i < expDir.NumberOfFunctions - 1; i++) {
            LPCSTR fnName = rvaToVa!LPCSTR(peBase, addrOfNames[i]);
            WORD fnOrd = addrOfNameOrds[i];
            PVOID fnAddr = rvaToVa!PVOID(peBase, addrOfFuncs[fnOrd]);
            
            if (!strncmp(fnName, "Zw", 2) && addrOfFuncs[fnOrd] == beginAddr) {

                auto syscall = new SystemCall(
                        ssn,
                        lpcstrToStr(fnName),
                        fnAddr,
                    );

                // apparently the new operator returns a pointer so we need to deref.
                systemCalls.push_back(*syscall);

                ssn++;
                break;
            }
        }
        currentIndex++;
    }

    return systemCalls;
}

void main() {
    
    auto syscalls = getSystemCalls();

    foreach (SystemCall syscall ; syscalls) {
        writefln("%s - %d (0x%x)", syscall.Name, syscall.Ssn, syscall.Ssn);
    }

}