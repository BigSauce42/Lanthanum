#include "Common.h"

const BYTE shell_code[] =
{
     0x50, //push rax
     0x51, //push rcx
     0x48, 0x83, 0xEC, 0x28, //sub rsp, 0x28
     0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //movabs rax, LoadLibraryW
     0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //movabs rcx, dll_path
     0xFF, 0xD0, //call rax
     0x48, 0x83, 0xC4, 0x28, //add rsp, 0x28
     0x59, //pop rcx
     0x58, //pop rax
     0xC3  //retd
};

const std::wstring OpenFileDialog()
{

    wchar_t file_path[MAX_PATH];

    OPENFILENAMEW open_file_dialog{ 0 };
    open_file_dialog.lStructSize = sizeof OPENFILENAMEW;
    open_file_dialog.hwndOwner = NULL;
    open_file_dialog.lpstrFile = file_path;
    open_file_dialog.lpstrFile[0] = '\0';
    open_file_dialog.nMaxFile = MAX_PATH;
    open_file_dialog.lpstrFilter = L".dll\0";
    open_file_dialog.nFilterIndex = 1;
    open_file_dialog.lpstrFileTitle = NULL;
    open_file_dialog.nMaxFileTitle = 0;
    open_file_dialog.lpstrInitialDir = NULL;
    open_file_dialog.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&open_file_dialog))
        return std::wstring(file_path);

}

int main()
{
    
    std::string process_name{ "" };
    std::cout << "Enter process name(e.g notepad.exe): ";
    std::cin >> process_name;

    const std::wstring dll_path = OpenFileDialog();

    Process target_process(process_name, PROCESS_ALL_ACCESS);
    
    if(!target_process.Valid())
    { 
        printf_s("Failed to find process: %x\n", GetLastError());
        return -1;
    }

    //Allocate memory in the process to hold our dll path
    uint64_t path_memory = (uint64_t)target_process.Alloc(0, MAX_PATH, PAGE_READWRITE);

    if (!path_memory)
    {
        printf_s("Failed to allocate remote memory for dll path: %x\n", GetLastError);
        return -1;
    }

    //Write the path to the allocated memory
    target_process.Write(path_memory, MAX_PATH, (PVOID)dll_path.c_str());
    //Allocate remote memory for our shellcode
    uint64_t shellcode_memory = (uint64_t)target_process.Alloc(0, sizeof shell_code, PAGE_EXECUTE_READWRITE);

    if (!shellcode_memory)
    {
        printf_s("Failed to allocate remote memory for shell code: %x\n", GetLastError);
        return -1;
    }

    //Write our shellcode to the remote memory
    target_process.Write(shellcode_memory, sizeof shell_code, (PVOID)shell_code);

    //Ghetto af
    uint64_t loadlibrary_addr = reinterpret_cast<uint64_t>(&LoadLibraryW);

    //Write the dynamic data in the shellcode
    target_process.Write(shellcode_memory + 8, 0x8, &loadlibrary_addr);
    target_process.Write(shellcode_memory + 18, 0x8, &path_memory);

    target_process.HijackThread(shellcode_memory);

    return 0;

}