#pragma once
#include <optional>
#include <iostream>
#include <vector>

#include "util.hpp"

#include <Psapi.h>

namespace remote_process
{
	struct remote_t
	{
		util::smart_handle processHandle;
		std::vector<HMODULE> dlls;
	};

	// std::optional added for meme purposes
	inline std::optional<remote_t> get_remote_process_info(DWORD pid)
	{
		remote_t proc{
			util::smart_handle(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid), &CloseHandle),
			{}
		};

		if (proc.processHandle.get() == NULL)
		{
			std::cout << "Failed to open remote process." << std::endl;
			return std::nullopt;
		}

		DWORD modulesLength;
		if (!EnumProcessModulesEx(proc.processHandle.get(), NULL, NULL, &modulesLength, LIST_MODULES_ALL)) {
			std::cout << "Failed to get remote module count." << std::endl;
			return std::nullopt;
		}

		proc.dlls.reserve(modulesLength);
		
		// Can't think of a better solution to populate the vector directly :(
		HMODULE hMods[1024];
		DWORD cbNeeded;
		if (!EnumProcessModulesEx(proc.processHandle.get(), hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
			std::cout << "Failed to get remote module handles." << std::endl;
			return std::nullopt;
		}

		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)) - 1; i++)
		{
			proc.dlls.push_back(hMods[i]);
		}
		return proc;
	}
}