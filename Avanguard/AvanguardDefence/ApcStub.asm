; 'AMD64' defined in MASM command line in a properties of the project (for the x64 only)

IFNDEF AMD64
    .686P
    .XMM
    .MODEL FLAT, STDCALL
    EXTERN ApcHandler@12: NEAR
ELSE
    EXTERN ApcHandler: NEAR
ENDIF

EXTERN OriginalApcDispatcher: NEAR

.CODE
IFDEF AMD64
    ; [x64] KiUserApcDispatcher(CONTEXT Context):
    KiApcStub PROC PUBLIC
        ; RSP = CONTEXT* Context to continue execution
        ; ApcRoutine = Context->P1Home

        push rax
        push rcx
        ; RSP    -> RCX
        ; RSP+8  :  RAX
        ; RSP+16 :  Context->P1Home (ApcRoutine)
        ; RSP+24 :  Context->P2Home
        ; ...    :  ...

        lea rcx, [rsp + 2 * sizeof(QWORD)]
        call ApcHandler ; ApcHandler(&Context)
        pop rcx
        pop rax
        jmp qword ptr [OriginalApcDispatcher]
    KiApcStub ENDP
ELSE
    ; [x32] KiUserApcDispatcher(PVOID NormalRoutine, PVOID SystemArgument1, PVOID SystemArgument2, CONTEXT Context):
    KiApcStub PROC PUBLIC
        push ebp
        mov ebp, esp
        push eax ; Save as EAX is volatile here

        ; EBP    -> EBP of a previous frame
        ; EBP+4  :  NormalRoutine (ApcRoutine)
        ; EBP+8  :  SystemArgument1 (Argument)
        ; EBP+12 :  SystemArgument2
        ; EBP+16 :  Context
        ; ...    :  ...

        mov eax, ebp
        add eax, 16
        push eax ; Context
        push [ebp + 8] ; Argument
        push [ebp + 4] ; ApcRoutine
        call ApcHandler@12

        pop eax
        mov esp, ebp
        pop ebp
        jmp dword ptr [OriginalApcDispatcher]
    KiApcStub ENDP
ENDIF

END