#include <string>
#include <iostream>
#include <cstdio>
#include <fstream>
#include "Minhook/MinHook.h"
#include "PatternScanner.hpp"

namespace Patterns {
    UINT64 Error = (UINT64)PTRSCAN::PatternScan(GetModuleHandle(NULL), "48 89 5C 24 10 57 48 81");
	UINT64 Modify = (UINT64)PTRSCAN::PatternScan(GetModuleHandle(NULL), "48 89 5C 24 08 48 89 74 24 10 48");
	UINT64 Req = (UINT64)PTRSCAN::PatternScan(GetModuleHandle(NULL), "48 89 5C 24 20 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C");
}

namespace Logger {
	void Log(std::string Message) {
		std::ofstream outfile("KeyAuth.Log");

		outfile << Message << std::endl;

		outfile.close();
	}
}

namespace Hooks {	
	using ReqHooked = std::string(*)(std::string data, std::string url);
	ReqHooked ReqLook = nullptr;

	inline void NothingHook() {
		// do nothing ...
	}

	inline std::string ReqHook(std::string data, std::string url) {
		if (data.find("type=log") != std::string::npos) {
			// can change data example: type=log&pcuser=&message=&sessionid=&name=&ownerid=
			auto Response = ReqLook(data, url);
			Logger::Log(Response);
			return Response;
		}
		if (data.find("type=webhook") != std::string::npos) {
			// can change data
			auto Response = ReqLook(data, url);
			Logger::Log(Response);
			return Response;
		}

		if (data.find("type=login") != std::string::npos) {
			auto Response = ReqLook(data, url);
			Logger::Log(Response);
			// you can bypass keyauth here! just need to find the correct string can you do it?
			return Response;
		}

		return "";
	}

	inline void Start() {
		if (MH_Initialize() != MH_OK) {
			printf("Error Initializing MinHook");
		}

		if (MH_CreateHook((void*)Patterns::Modify, &NothingHook, NULL) != MH_OK) {
			printf("Error Hooking Modify");
		}

		if (MH_CreateHook((void*)Patterns::Error, &NothingHook, NULL) != MH_OK) {
			printf("Error Hooking Error");
		}

		if (MH_CreateHook((void*)Patterns::Req, &ReqHook, reinterpret_cast<LPVOID*>(&ReqLook)) != MH_OK) {
			printf("Error Hooking Req");
		}

		if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
			printf("Error Enabling Hooks");
		}
	}
}