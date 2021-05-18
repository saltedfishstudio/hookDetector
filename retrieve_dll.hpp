#pragma once
#include <string>
#include <filesystem>
#include <vector>
#include <iostream>

#include <Windows.h>

namespace dll
{
	struct info_t
	{
		HMODULE module;
		std::vector<std::uint8_t> local_bytes;
		std::uint8_t* fileMapping;
		std::wstring path;
		std::wstring name;
	};

	inline std::vector<std::uint8_t> map_to_local(remote_process::remote_t& proc, const HMODULE& dll)
	{
		MEMORY_BASIC_INFORMATION memory_basic_information = { 0 };
		std::size_t dll_size = 0;
		auto base = reinterpret_cast<std::uint64_t>(dll);

		// Loop to get full dll size
		while (TRUE) {
			if (VirtualQueryEx(proc.processHandle.get(), reinterpret_cast<void*>(base), &memory_basic_information, sizeof(memory_basic_information))) {
				if (memory_basic_information.AllocationBase == dll) {
					dll_size += memory_basic_information.RegionSize;
					base += memory_basic_information.RegionSize;
				}
				else {
					break;
				}
			}
			else {
				std::cout << "[!] Failed to VirtualQueryEx remote process memory!" << std::endl;
				return {};
			}
		}
		std::vector<std::uint8_t> local_bytes;

		local_bytes.resize(dll_size); // we only reserve it, but the vector wouldn't realize it's been filled so we use resize so .size() matches

		if (!ReadProcessMemory(proc.processHandle.get(), dll, local_bytes.data(), dll_size, nullptr))
		{
			return {};
		}

		return local_bytes;
	}

	inline std::uint8_t* map_file_from_disk(std::wstring_view module_path) {
		// https://stackoverflow.com/questions/48178586/how-to-disable-wow64-file-system-redirection-for-getmodulefilenameex
		wchar_t temp_string[MAX_PATH] = L"\\\\?\\globalroot";

		if (0 != wcscat_s(temp_string, MAX_PATH, module_path.data()))
			return nullptr;

		const auto h_disk = util::smart_handle(
			CreateFileW(temp_string, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr),
			&CloseHandle
		);

		if (h_disk.get() == INVALID_HANDLE_VALUE)
			return nullptr;

		const auto h_mapping = util::smart_handle(
			CreateFileMapping(h_disk.get(), nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr),
			&CloseHandle
		);

		if (h_mapping.get() == INVALID_HANDLE_VALUE)
			return nullptr;

		return static_cast<std::uint8_t*>(MapViewOfFile(h_mapping.get(), FILE_MAP_READ, 0, 0, 0));
	}

	inline info_t retrieve(remote_process::remote_t& proc, const HMODULE& dll)
	{
		info_t info{};

		info.module = dll;

		const auto module_path = util::get_string_from_windows_api<TCHAR>([&](TCHAR* buffer, const int size)
			{
				return GetMappedFileNameW(proc.processHandle.get(), dll, buffer, size);
			});

		info.path = module_path;

		info.name = std::wstring(wcsrchr(module_path.c_str(), L'\\') + 1);

		info.local_bytes = map_to_local(proc, dll);

		info.fileMapping = map_file_from_disk(info.path);

		return info;
	}
}