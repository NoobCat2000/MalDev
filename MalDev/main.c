#include "pch.h"

int main() {
	wprintf(L"TEB Base Address: %p\n", NtCurrentTeb());
	return 0;
}