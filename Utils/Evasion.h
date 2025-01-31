#pragma once

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_BIG,
    UWOP_EPILOG,
    UWOP_SPARE_CODE,
    UWOP_SAVE_XMM128,
    UWOP_SAVE_XMM128BIG,
    UWOP_PUSH_MACH_FRAME,
};

typedef enum _REGISTERS {
    RAX = 0,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15
} REGISTERS;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    union {
        OPTIONAL ULONG ExceptionHandler;
        OPTIONAL ULONG FunctionEntry;
    };
    OPTIONAL ULONG ExceptionData[];
} UNWIND_INFO, * PUNWIND_INFO;

LPVOID SpoofCall(LPVOID lpRoutine, ...);

UINT64 FindGadget
(
    _In_ DWORD dwGadgetType,
    _Out_ PDWORD pcbStackFrame
);

DWORD GetStackFrameSize
(
    _In_ HMODULE hModule,
    _In_ PUNWIND_INFO pUnwindInfo
);

UINT64 FindSetFpProlog
(
    _Out_ PDWORD pdwFrameOffset,
    _Out_ PDWORD pdwFrameSize,
    _Out_ PDWORD pdwRandomOffset
);

UINT64 FindSaveRbp
(
    _Out_ PDWORD pdwFrameOffset,
    _Out_ PDWORD pdwFrameSize,
    _Out_ PDWORD pdwRandomOffset
);

BOOL SetupStackSpoofing(void);