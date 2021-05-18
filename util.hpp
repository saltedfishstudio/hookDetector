#pragma once
#include <memory>
#include <Windows.h>
#include <string>

namespace util
{
	using smart_handle = std::unique_ptr<void, decltype(&CloseHandle)>;

	// https://stackoverflow.com/posts/54491532
	template <typename TChar, typename TStringGetterFunc>
	std::basic_string<TChar> get_string_from_windows_api(TStringGetterFunc string_getter, int initial_size = 0)
	{
		if (initial_size <= 0)
		{
			initial_size = MAX_PATH;
		}

		std::basic_string<TChar> result(initial_size, 0);
		for (;;) // kinda ugly ngl
		{
			auto length = string_getter(result.data(), result.length());
			if (length == 0)
			{
				return std::basic_string<TChar>();
			}

			if (length < result.length() - 1)
			{
				result.resize(length);
				result.shrink_to_fit();
				return result;
			}

			result.resize(result.length() * 2);
		}
	}
}

namespace image
{
	inline PIMAGE_EXPORT_DIRECTORY get_export_directory(const std::uint64_t base)
	{
		const auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);

		const auto nt_sig = reinterpret_cast<DWORD*>(base + dos->e_lfanew);
		if (*nt_sig != IMAGE_NT_SIGNATURE) { // Corrupted image
			return nullptr;
		}

		auto coff_header = reinterpret_cast<PIMAGE_FILE_HEADER>(nt_sig + 1);
		if (coff_header->Machine == IMAGE_FILE_MACHINE_AMD64) {
			auto oh64 = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(coff_header + 1);
			if (IMAGE_DIRECTORY_ENTRY_EXPORT >= oh64->NumberOfRvaAndSizes) {
				return nullptr;
			}
			const auto rva = oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			return reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + rva);
		}
		else if (coff_header->Machine == IMAGE_FILE_MACHINE_I386) {
			auto oh32 = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(coff_header + 1);
			if (IMAGE_DIRECTORY_ENTRY_EXPORT >= oh32->NumberOfRvaAndSizes) {
				return nullptr;
			}
			const auto rva = oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			return reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + rva);
		}
		return nullptr;
	}

	inline std::uint32_t get_import_descriptor_va(uint64_t base)
	{
		const auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);

		const auto nt_sig = reinterpret_cast<DWORD*>(base + dos->e_lfanew);
		if (*nt_sig != IMAGE_NT_SIGNATURE) { // Corrupted image
			return 0;
		}

		auto coff_header = reinterpret_cast<PIMAGE_FILE_HEADER>(nt_sig + 1);
		if (coff_header->Machine == IMAGE_FILE_MACHINE_AMD64) {
			auto oh64 = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(coff_header + 1);
			if (IMAGE_DIRECTORY_ENTRY_IMPORT >= oh64->NumberOfRvaAndSizes) {
				return 0;
			}
			return oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		}
		else if (coff_header->Machine == IMAGE_FILE_MACHINE_I386) {
			auto oh32 = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(coff_header + 1);
			if (IMAGE_DIRECTORY_ENTRY_IMPORT >= oh32->NumberOfRvaAndSizes) {
				return 0;
			}
			return oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		}
		return 0;
	}

	// Returns the .text section for most dlls
	inline uint64_t get_text_section(const uint64_t base)
	{
		const auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);

		const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE) { // Corrupted image
			return 0;
		}

		PIMAGE_FILE_HEADER coffFileHeader = &nt_headers->FileHeader;

		WORD sizeOfOptionalheader = coffFileHeader->SizeOfOptionalHeader;
		PIMAGE_OPTIONAL_HEADER optional_header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>((PBYTE)nt_headers + 0x18);

		PIMAGE_SECTION_HEADER section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>((PBYTE)optional_header + sizeOfOptionalheader);

		for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
		{
			// We could maybe rewrite it and scan for entry point instead of hardcodign the section name
			if (strcmp((char*)section_headers[i].Name, ".text") == 0)
				return section_headers[i].VirtualAddress + base;
		}
		return 0;
	}

	inline size_t get_text_section_size(const uint64_t base)
	{
		const auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);

		const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE) { // Corrupted image
			return 0;
		}

		const PIMAGE_FILE_HEADER coff_file_header = &nt_headers->FileHeader;

		const WORD size_of_optional_header = coff_file_header->SizeOfOptionalHeader;
		const auto optional_header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>((PBYTE)nt_headers + 0x18);

		const auto section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>((PBYTE)optional_header + size_of_optional_header);

		for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
		{
			if (strcmp((char*)section_headers[i].Name, ".text") == 0)
				return section_headers[i].Misc.VirtualSize;
		}
		return 0;
	}
}