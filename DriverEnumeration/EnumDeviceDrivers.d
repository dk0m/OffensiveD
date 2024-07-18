module DriverEnumeration.EnumDeviceDrivers;

import core.sys.windows.windows;
import core.sys.windows.psapi;
import core.stdcpp.vector;
import std.stdio;

pragma(lib, "psapi.lib");


vector!LPVOID getDriversBases() {

    auto drvBases = vector!LPVOID(Default);

    LPVOID[1024] driverBases;
    DWORD neededSize;

    EnumDeviceDrivers(&driverBases[0], driverBases.sizeof, &neededSize);

    SIZE_T amountOfDrvs = neededSize / LPVOID.sizeof;


    for (SIZE_T i = 0; i < amountOfDrvs; i++) {
        drvBases.push_back(driverBases[i]);
    }

    return drvBases;
}

CHAR[MAX_PATH] getDriverName(LPVOID drvBase) {
    CHAR[MAX_PATH] drvName;

    GetDeviceDriverBaseNameA(drvBase, &drvName[0], drvName.sizeof);
    
    return drvName;
}

CHAR[MAX_PATH] getDriverFileName(LPVOID drvBase) {
    CHAR[MAX_PATH] drvFileName;

    GetDeviceDriverFileNameA(drvBase, &drvFileName[0], drvFileName.sizeof);

    return drvFileName;
}
