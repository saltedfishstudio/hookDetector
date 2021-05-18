#pragma once

#include <Windows.h>
#include <TlHelp32.h>
namespace hook
{
	// https://codereview.stackexchange.com/questions/419/converting-between-stdwstring-and-stdstring
	inline std::wstring string_to_wide_string(const std::string_view str)
	{
		const int s_length = static_cast<int>(str.length()) + 1;
		const int len = MultiByteToWideChar(CP_ACP, 0, str.data(), s_length, 0, 0);
		const auto buf = new wchar_t[len];
		MultiByteToWideChar(CP_ACP, 0, str.data(), s_length, buf, len);
		std::wstring r(buf);
		delete[] buf;
		return r;
	}

	inline uint64_t get_remote_module_base_addr(const DWORD pid, const std::string_view mod_name)
	{
		const auto snap_shot = util::smart_handle(CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid),
			&CloseHandle);

		if (snap_shot.get() == INVALID_HANDLE_VALUE) {
			return 0;
		}

		auto w_mod_name = string_to_wide_string(mod_name);

		MODULEENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);

		for (Module32First(snap_shot.get(), &entry); Module32Next(snap_shot.get(), &entry);)
			if (std::wcscmp(w_mod_name.data(), entry.szModule) == 0)
				return reinterpret_cast<uint64_t>(entry.modBaseAddr);

		return 0;
	}

	inline void find_iat_hooks(DWORD pid, const dll::info_t& dll_info)
	{
		const auto remote_base = reinterpret_cast<uint64_t>(dll_info.local_bytes.data());
		const auto dll_disk_mapping = reinterpret_cast<uint64_t>(dll_info.fileMapping);

		const auto import_desc_va_memory = image::get_import_descriptor_va(remote_base);
		const auto import_desc_va_disk = image::get_import_descriptor_va(dll_disk_mapping);

		if (!import_desc_va_disk || !import_desc_va_memory)
			return;

		auto import_descriptor_mem = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(remote_base + import_desc_va_memory);
		auto import_descriptor_disk = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(dll_disk_mapping + import_desc_va_disk);

		std::vector<std::string> patched_functions;

		for (;
			import_descriptor_mem->Name != NULL && import_descriptor_disk->Name != NULL;
			import_descriptor_mem++, import_descriptor_disk++
			)
		{
			const auto library_name = reinterpret_cast<LPCSTR>(import_descriptor_mem->Name + remote_base);
			auto local_library = LoadLibraryA(library_name);
			const auto remote_library = get_remote_module_base_addr(pid, library_name);

			if (remote_library == 0)
			{
				//Skipping IAT Hook Detection for this module
				continue;
			}

			auto original_first_thunk_mem = reinterpret_cast<PIMAGE_THUNK_DATA>(remote_base + import_descriptor_mem->OriginalFirstThunk);
			auto original_first_thunk_disk = reinterpret_cast<PIMAGE_THUNK_DATA>(dll_disk_mapping + import_descriptor_disk->OriginalFirstThunk);

			for (
				auto first_thunk_disk = reinterpret_cast<PIMAGE_THUNK_DATA>(dll_disk_mapping + import_descriptor_disk->FirstThunk),
				first_thunk_mem = reinterpret_cast<PIMAGE_THUNK_DATA>(remote_base + import_descriptor_mem->FirstThunk);

				original_first_thunk_mem->u1.AddressOfData != NULL && original_first_thunk_disk->u1.AddressOfData != NULL;

				original_first_thunk_mem++, original_first_thunk_disk++, first_thunk_mem++, first_thunk_disk++
				)
			{
				const std::uint64_t real_value = first_thunk_mem->u1.Function;
				std::uint64_t expected_value = 0;
				std::string fct;
				if (first_thunk_disk->u1.Ordinal & IMAGE_ORDINAL_FLAG) // Imported by Ordinal
				{
					const auto local_offset = reinterpret_cast<std::uint64_t>(GetProcAddress(local_library, reinterpret_cast<LPCSTR>(first_thunk_disk->u1.Ordinal & 0xFFFF))) - reinterpret_cast<std::uint64_t>(local_library);
					expected_value = remote_library + local_offset;
					fct = "Ordinal: " + std::to_string(first_thunk_disk->u1.Ordinal & 0xFFFF);
				}
				else // Imported by Name
				{
					auto function_name_disk = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(dll_disk_mapping + first_thunk_disk->u1.AddressOfData);
					fct = std::string(function_name_disk->Name);
					const auto local_offset = reinterpret_cast<std::uint64_t>(GetProcAddress(local_library, function_name_disk->Name)) - reinterpret_cast<std::uint64_t>(local_library);
					expected_value = remote_library + local_offset;
				}

				// If the expected value we get by using the Exporttable doesn't match the actual value
				if (real_value != expected_value) {
					patched_functions.push_back(fct);
				}
			}
		}

		if (!patched_functions.empty()) {
			std::wcout << patched_functions.size() << " IAT Hooks found:" << std::endl;
			for (auto& fct : patched_functions) {
				std::cout << "\t" << fct << std::endl;
			}
			std::cout << "\n\n";
		}
	}
}