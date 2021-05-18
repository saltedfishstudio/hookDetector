#include "get_remote_process.hpp"
#include "retrieve_dll.hpp"

#include "inline_hooks.hpp"
#include "iat_hook.hpp"

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		std::cout << "Please give me a PID to work with!" << std::endl;
		std::cout << "Example: detect.exe 1234";
		return 0;
	}
	DWORD pid = std::stoi(argv[1]);

	if (pid == GetCurrentProcessId())
	{
		std::cout << "No. I won't check myself" << std::endl;
		return 0;
	}

	std::cout << "Checking " << argv[1] << ". Please wait...\n\n" << std::endl;

	auto remote_proc = remote_process::get_remote_process_info(pid);
	if (!remote_proc.has_value())
		return 0;

	std::vector<std::wstring> skipped_modules;
	for (const auto& dll : remote_proc.value().dlls)
	{
		auto dll_info = dll::retrieve(remote_proc.value(), dll);

		if (dll_info.local_bytes.empty())
		{
			skipped_modules.push_back(dll_info.name);
		}
		else
		{
			std::wcout << "Checking " << dll_info.name << "\n";
			hook::find_inline_hooks(dll_info);
			hook::find_iat_hooks(pid, dll_info);
		}
		// Free memory to save the environment
		dll_info.local_bytes.clear();
		dll_info.local_bytes.shrink_to_fit();
		UnmapViewOfFile(dll_info.fileMapping);
	}

	if (!skipped_modules.empty()) {
		std::cout << "\n\nSkipped modules:" << std::endl;
		for (auto& name : skipped_modules)
		{
			std::wcout << "\t" << name << std::endl;
		}
	}

	std::cout << "Done." << std::endl;
}