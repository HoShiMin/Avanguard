#pragma once

typedef struct {
    struct {
        HMODULE hAvn;
        HMODULE hNtdll;
        HMODULE hKernelBase;
        HMODULE hKernel32;
    } hModules;
    struct {
        BOOLEAN IsAvnStaticLoaded : 1;
        BOOLEAN IsAvnInitialized : 1;
        BOOLEAN IsAvnStarted : 1;
        BOOLEAN Reserved : 5;
    } Flags;
} AVN_GLOBALS, *PAVN_GLOBALS;

extern AVN_GLOBALS AvnGlobals;