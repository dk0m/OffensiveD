module ApiHooking.ApiHooking;

import core.sys.windows.windows;
import core.sys.windows.psapi;
import std.stdio;

pragma(lib, "user32.lib");

extern (C) void *memcpy(void *to, const void *from, size_t numBytes);

class ApiHook {

    string moduleName;
    string procedureName;
    PVOID targetFunction;
    PVOID hookFunction;

    BYTE[12] orgBytes;
    DWORD oldProtection;

    this(string moduleName, string procedureName, PVOID hookFunction) {
        this.moduleName = moduleName;
        this.procedureName = procedureName;
        this.hookFunction = hookFunction;
        this.targetFunction = cast(PVOID)GetProcAddress(GetModuleHandleA(cast(LPCSTR)this.moduleName), cast(LPCSTR)this.procedureName);
    }

    void enable() {

        // x64 mov rax jmp rax byte array, only x64 platforms for now.
        BYTE[12] hookByteArray = [ 0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xE0 ];

        PVOID fnAddr = this.targetFunction;

        memcpy(&this.orgBytes[0], fnAddr, hookByteArray.sizeof); // putting org bytes
        memcpy(&hookByteArray[2], &this.hookFunction, PVOID.sizeof); // putting hook function address

        DWORD oldProtection;
        VirtualProtect(fnAddr, hookByteArray.sizeof, PAGE_EXECUTE_READWRITE, &oldProtection);

        this.oldProtection = oldProtection;

        memcpy(fnAddr, &hookByteArray[0], hookByteArray.sizeof);
    }

    void disable() {
        PVOID fnAddr = this.targetFunction;

        memcpy(fnAddr, &this.orgBytes[0], this.orgBytes.sizeof);

        DWORD oldProtection;
        VirtualProtect(fnAddr, this.orgBytes.sizeof, PAGE_EXECUTE_READWRITE, &oldProtection);

        this.oldProtection = oldProtection;

    }
}

int msgBoxAHook(HWND, LPCSTR, LPCSTR, UINT) {
    return MessageBoxW(NULL, "Hooked!", "Hooked!", 0);
}

void main() {
    auto hook = new ApiHook("user32.dll", "MessageBoxA", &msgBoxAHook);
    hook.enable();

    MessageBoxA(
        NULL,
        "yo",
        "yo",
        0
    );

    hook.disable();

    MessageBoxA(
        NULL,
        "yo",
        "yo",
        0
    );

}
