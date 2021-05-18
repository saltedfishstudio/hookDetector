#pragma once
#include <algorithm>
#include <iostream>

#include <Windows.h>

#include "util.hpp"

namespace hook
{
	inline void find_inline_hooks(const dll::info_t& dll_info)
	{
		std::vector<DWORD> rvas;

		const auto remote_base = reinterpret_cast<uint64_t>(dll_info.local_bytes.data());
		const auto dll_disk_mapping = reinterpret_cast<uint64_t>(dll_info.fileMapping);

		const auto in_memory_main = reinterpret_cast<std::uint8_t*>(image::get_text_section(remote_base));
		const auto on_disk_main = reinterpret_cast<std::uint8_t*>(image::get_text_section(dll_disk_mapping));

		const size_t main_section_size = image::get_text_section_size(remote_base); // Both sizes should be equal, so we only get it once.

		if (!in_memory_main || !on_disk_main || main_section_size == 0)
		{
			return;
		}

		auto compare_memory = [](const std::uint8_t* a, const std::uint8_t* b, const size_t size, const int offset = 0)
		{
			const int res = -1;
			if (size < 1)
				return res;
			for (int i = offset; i < size; ++i)
				if (a[i] != b[i])
					return i;
			return res;
		};

		for (
			int compare_memory_result = compare_memory(on_disk_main, in_memory_main, main_section_size);
			compare_memory_result != -1;
			compare_memory_result = compare_memory(on_disk_main, in_memory_main, main_section_size, ++compare_memory_result)
			)
		{
			const auto rva = reinterpret_cast<std::uint32_t>(in_memory_main + compare_memory_result - remote_base);
			rvas.push_back(rva);
		}

		auto get_exported_ordinal_by_rva = [](std::uint32_t rva, std::uint64_t base)
		{
			const auto eat = image::get_export_directory(base);
			int ordinal = -1;
			if (!eat)
				return ordinal;
			const auto eat_functions = reinterpret_cast<std::uint32_t*>(eat->AddressOfFunctions + base);
			uint32_t best_match = 0;
			for (int i = 0; i < eat->NumberOfFunctions; i++)
			{
				const uint32_t delta = rva - eat_functions[i]; // Get difference between the eat function in memory and the one we expect in the main section
				if (delta == 0 || delta < best_match) // Simple search to find the eat that's closest to the rva
				{
					best_match = delta;
					ordinal = i;

					if (delta == 0) // Can't get any closer than that
						break;
				}
			}
			return ordinal;
		};

		std::vector<int> ordinals;

		for (const auto& rva : rvas)
		{
			auto ordinal = get_exported_ordinal_by_rva(rva, remote_base);
			if (ordinal == -1)
				continue;
			ordinals.push_back(ordinal);
		}

		// Could be replaced with std::ranges::unique() ?
		std::sort(ordinals.begin(), ordinals.end());
		ordinals.erase(std::unique(ordinals.begin(), ordinals.end()), ordinals.end());

		const auto ordinal_base = image::get_export_directory(remote_base)->Base;

		auto get_eot_by_ordinal = [](std::uint16_t ordinal, std::uint64_t base) {
			const auto eat = image::get_export_directory(base);
			const auto eot = reinterpret_cast<std::uint16_t*>(eat->AddressOfNameOrdinals + base);
			int res = -1;
			for (std::uint32_t i = 0; i < eat->NumberOfNames; i++) {
				if (eot[i] == ordinal) {
					res = i; // Keep type consistent.
					return res;
				}
			}
			return res;
		};

		if (ordinals.empty())
			return;

		std::cout << "\n" << ordinals.size() << " byte patched functions detected:" << std::endl;

		for (const int& ordinal : ordinals) {
			const auto eot = get_eot_by_ordinal(ordinal, remote_base);
			if (eot == -1)
				continue;
			const auto eat_aon = reinterpret_cast<std::uint32_t*>(image::get_export_directory(remote_base)->AddressOfNames + remote_base);
			const auto function_name = reinterpret_cast<char*>(remote_base + eat_aon[eot]);
			std::cout << "\t" << ordinal + ordinal_base << ": " << function_name << std::endl;
		}
		std::cout << "\n";
	}
}