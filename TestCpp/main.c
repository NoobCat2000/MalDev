#include <Windows.h>
#include <stdio.h>

int main() {
	CHAR szFlag[0x100];

	SecureZeroMemory(szFlag, sizeof(szFlag));
	puts("Nhap dap an:");
	fgets(szFlag, _countof(szFlag), stdin);
	szFlag[lstrlenA(szFlag) - 1] = '\0';
	if (!lstrcmpA(szFlag, "Lop PTMD")) {
		puts("Dap an dung");
	}
	else {
		puts("Dap an sai");
	}

	return 0;
}