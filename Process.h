#pragma once

class Process
{

private:
	HANDLE h_proc;
	uint16_t proc_id{ 0 };

public:
	Process(const std::string_view& process_name, std::uint32_t access_type)
	{

		HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		PROCESSENTRY32 proc_entry{ 0 };
		proc_entry.dwSize = sizeof PROCESSENTRY32;

		Process32First(h_snapshot, &proc_entry);

		do
		{

			if (proc_entry.szExeFile == process_name)
			{

				proc_id = proc_entry.th32ProcessID;
				break;

			}

		} while (Process32Next(h_snapshot, &proc_entry));

		CloseHandle(h_snapshot);

		//Open a handle process
		h_proc = OpenProcess(access_type, false, proc_id);

	}

	//~Proc() { CloseHandle(h_proc); }

	BOOLEAN Valid()
	{
		return (h_proc != 0);
	}

	PVOID Alloc(uint64_t address, size_t size, uint32_t protect)
	{
		PVOID new_mem = VirtualAllocEx(h_proc, (LPVOID)address, size, MEM_COMMIT | MEM_RESERVE, protect);

		if (!new_mem)
			printf_s("VirtualAllocEx failed: %x\n", GetLastError());

		return new_mem;
	}

	void Free(uint64_t address, size_t size)
	{

		if (!VirtualFreeEx(h_proc, (LPVOID)address, size, MEM_RELEASE))
			printf_s("VirtualFreeEx failed: %x\n", GetLastError());

	}

	template <typename T = PVOID>
	T Read(uint64_t address, size_t size)
	{

		T buffer{ 0 };

		if (!ReadProcessMemory(h_proc, (LPVOID)address, &buffer, size, nullptr))
			printf_s("ReadProcessMemory failed: %x\n", GetLastError());

		return buffer;

	}

	void Write(uint64_t address, size_t size, PVOID buffer)
	{

		if (!WriteProcessMemory(h_proc, (LPVOID)address, buffer, size, nullptr))
			printf_s("WriteProcessMemoryFailed failed: %x\n", GetLastError());

	}

	void HijackThread(uint64_t new_rip)
	{

		HANDLE h_threadsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		THREADENTRY32 thread_entry{ 0 };

		thread_entry.dwSize = sizeof THREADENTRY32;
		Thread32First(h_threadsnap, &thread_entry);

		do
		{

			if (thread_entry.th32OwnerProcessID == proc_id)
				break;

		} while (Thread32Next(h_threadsnap, &thread_entry));

		CloseHandle(h_threadsnap);

		HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, thread_entry.th32ThreadID);

		DWORD thread = SuspendThread(h_thread);

		CONTEXT thread_context{ 0 };
		thread_context.ContextFlags = CONTEXT_FULL;

		if (!GetThreadContext(h_thread, &thread_context))
			printf_s("GetThreadContext failed: %x\n", GetLastError());

		thread_context.Rip = new_rip;

		if (!SetThreadContext(h_thread, &thread_context))
			printf_s("SetThreadContext failed: %x\n", GetLastError());

		ResumeThread(h_thread);

		CloseHandle(h_thread);

	}

	void NewThread(uint64_t address, uint64_t param)
	{

		CreateRemoteThread(h_proc, nullptr, 0, LPTHREAD_START_ROUTINE(address), (PVOID)param, 0, nullptr);

	}

	MEMORY_BASIC_INFORMATION Query(uint64_t address)
	{

		MEMORY_BASIC_INFORMATION memory_info{ 0 };

		if (!VirtualQueryEx(h_proc, (PVOID)address, &memory_info, sizeof memory_info))
			printf_s("VirtualQueryEx failed %x\n: ", GetLastError());

		return memory_info;

	}

};