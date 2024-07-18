module PeImageParsing.Parser;

import core.sys.windows.windows;
import core.stdcpp.vector;
import std.stdio;
import std.string;


T rvaToVa(T) (DWORD_PTR peBase, DWORD offset) {
    return cast(T)(peBase + offset);
}

PVOID getImage(string targetMod) {
    return cast(PVOID)GetModuleHandleA(cast(LPCSTR)targetMod);
}


class PeHeaders {

    PIMAGE_DOS_HEADER dosHdr;
    PIMAGE_NT_HEADERS ntHdrs;
    IMAGE_OPTIONAL_HEADER optHdr;
    IMAGE_FILE_HEADER fileHdr;

    this(PIMAGE_DOS_HEADER dosHdr, PIMAGE_NT_HEADERS ntHdrs, IMAGE_OPTIONAL_HEADER optHdr, IMAGE_FILE_HEADER fileHdr) {
        this.dosHdr = dosHdr;
        this.ntHdrs = ntHdrs;
        this.optHdr = optHdr;
        this.fileHdr = fileHdr;
    }
}

class PeDirectories {

    PIMAGE_EXPORT_DIRECTORY exportDirectory;
    PIMAGE_IMPORT_DESCRIPTOR importDirectory;
    PIMAGE_TLS_DIRECTORY tlsDirectory;
    PIMAGE_BASE_RELOCATION relocsDirectory;
    PIMAGE_RUNTIME_FUNCTION_ENTRY rtfDirectory;

    this(PIMAGE_EXPORT_DIRECTORY expDir, PIMAGE_IMPORT_DESCRIPTOR impDir, PIMAGE_TLS_DIRECTORY tlsDir, PIMAGE_BASE_RELOCATION relocsDir, PIMAGE_RUNTIME_FUNCTION_ENTRY rtfDir) {
        this.exportDirectory = expDir;
        this.importDirectory = impDir;
        this.tlsDirectory = tlsDir;
        this.relocsDirectory = relocsDir;
        this.rtfDirectory = rtfDir;
    }
}


class PeImage {

    DWORD_PTR peBase;
    PeHeaders peHeaders;
    PeDirectories peDirectories;
    vector!PIMAGE_SECTION_HEADER sections;

    this(DWORD_PTR peBase, PeHeaders peHdrs, PeDirectories peDirs, vector!PIMAGE_SECTION_HEADER sections) {
        this.peBase = peBase;
        this.peHeaders = peHdrs;
        this.peDirectories = peDirs;
        this.sections = sections;
    }
}


string byteArrayToStr(BYTE[IMAGE_SIZEOF_SHORT_NAME] byteArray) {

    string finalStr = "";

    foreach(char character ; byteArray) {
        finalStr ~= character;
    }

    return finalStr;
}


PeImage parsePeImage(string targetMod) {

    auto peImage = getImage(targetMod);
    auto peBase = cast(DWORD_PTR)peImage;

    PIMAGE_DOS_HEADER dosHdr = cast(PIMAGE_DOS_HEADER)(peBase);
    
    PIMAGE_NT_HEADERS ntHdrs = rvaToVa!PIMAGE_NT_HEADERS(peBase, dosHdr.e_lfanew);

    IMAGE_OPTIONAL_HEADER optHdr = ntHdrs.OptionalHeader;
    IMAGE_FILE_HEADER fileHdr = ntHdrs.FileHeader;


    DWORD numberOfSecs = fileHdr.NumberOfSections;
    PIMAGE_SECTION_HEADER fSecHdr = rvaToVa!PIMAGE_SECTION_HEADER(cast(DWORD_PTR)ntHdrs, IMAGE_NT_HEADERS.sizeof);

    auto sections = vector!PIMAGE_SECTION_HEADER(Default);

    for (SIZE_T i = 0; i < numberOfSecs; i++) {
        sections.push_back(fSecHdr);
        fSecHdr = rvaToVa!PIMAGE_SECTION_HEADER(cast(DWORD_PTR)fSecHdr, IMAGE_SECTION_HEADER.sizeof);
    }
    

    auto exportDir = rvaToVa!PIMAGE_EXPORT_DIRECTORY(peBase, cast(DWORD)optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto importDir = rvaToVa!PIMAGE_IMPORT_DESCRIPTOR(peBase, cast(DWORD)optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    auto tlsDir = rvaToVa!PIMAGE_TLS_DIRECTORY(peBase, cast(DWORD)optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    auto relocsDir = rvaToVa!PIMAGE_BASE_RELOCATION(peBase, cast(DWORD)optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    auto runtimeFuncDir = rvaToVa!PIMAGE_RUNTIME_FUNCTION_ENTRY(peBase, cast(DWORD)optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

    auto peHdrs = new PeHeaders(dosHdr, ntHdrs, optHdr, fileHdr);
    auto peDirs = new PeDirectories(exportDir, importDir, tlsDir, relocsDir, runtimeFuncDir);

    auto returnedPeImage = new PeImage(peBase, peHdrs, peDirs, sections);

    return returnedPeImage;
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

void main() {
    // Parsing ntdll 
    PeImage peNtdll = parsePeImage("NTDLL");
    DWORD_PTR peBase = peNtdll.peBase;
    auto expDir = peNtdll.peDirectories.exportDirectory;

    PDWORD addrOfNames = rvaToVa!PDWORD(peBase, expDir.AddressOfNames);
    PDWORD addrOfFuncs = rvaToVa!PDWORD(peBase, expDir.AddressOfFunctions);
    PWORD addrOfNameOrds = rvaToVa!PWORD(peBase, expDir.AddressOfNameOrdinals);

    for (SIZE_T i = 0; i < expDir.NumberOfFunctions - 1; i++) {
        LPCSTR fnName = rvaToVa!LPCSTR(peBase, addrOfNames[i]);
        WORD fnOrd = addrOfNameOrds[i];
        PVOID fnAddr = rvaToVa!PVOID(peBase, addrOfFuncs[fnOrd]);

        string printableName = lpcstrToStr(fnName);

        writefln("%s - %d - 0x%x", printableName, fnOrd, fnAddr);
    }
}