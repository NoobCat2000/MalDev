#include <phnt_windows.h>
#include <phnt.h>
#include <stdio.h>

void test1() {
    PPEB pPeb = NtCurrentPeb();

    wprintf(L"pPeb->ProcessParameters->ImagePathName.Buffer: %p\n", pPeb->ProcessParameters->ImagePathName.Buffer);
    wprintf(L"pPeb->ProcessParameters->CommandLine.Buffer: %p\n", pPeb->ProcessParameters->CommandLine.Buffer);
}

int main() {
    test1();

    return 0;
}