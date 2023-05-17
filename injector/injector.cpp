#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>

DWORD get_pid_byname(const char* process_name)
{
    DWORD pid = 0;
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hsnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 process{};
        process.dwSize = sizeof(process);

        while (Process32Next(hsnap, &process))
        {
            if (!_stricmp(process.szExeFile, process_name)) {
                pid = process.th32ProcessID;
                break;
            }
        }
    }

    CloseHandle(hsnap);
    return pid;
}

int main()
{
    const char* dllpath = "c:\\\\test.dll"; //インジェクトしたいDLLパスを指定(バックスラッシュはエスケープ文字なので、二重に書く必要がある)
    int pid = get_pid_byname("HXD.exe"); //ターゲットプロセスのPID

    std::cout << "PID:" << pid << std::endl;

    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);//指定したプロセスのハンドルを開く

    LPVOID dll_path_addr = VirtualAllocEx(process_handle, nullptr, strlen(dllpath) + 1, MEM_COMMIT, PAGE_READWRITE);//メモリー確保

    WriteProcessMemory(process_handle, dll_path_addr, dllpath, strlen(dllpath) + 1, nullptr);//確保したメモリーにdllpathを書き込み

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC loadlibrary_addr = GetProcAddress(kernel32, "LoadLibraryA");
    if (loadlibrary_addr == NULL)
    {
        std::cout << "Failed to get the address of LoadLibraryA." << std::endl;
        return 1;
    }

    CreateRemoteThread(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)loadlibrary_addr, dll_path_addr, 0, NULL);


    std::cout << "done" << std::endl;
}
