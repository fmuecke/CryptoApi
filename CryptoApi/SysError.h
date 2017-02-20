#pragma once

#define VC_EXTRALEAN  // Exclude rarely-used stuff from Windows headers
#include <Windows.h>
#include <system_error>

namespace CryptoApi
{
	static void ThrowSysError()
	{
		auto code = ::GetLastError();
		auto err = std::error_code(code, std::system_category());
		throw std::system_error(err);
	}

	static void ThrowSysError(const char* msg)
	{
		auto code = ::GetLastError();
		auto err = std::error_code(code, std::system_category());
		throw std::system_error(err, msg);
	}

	static void ThrowSysError(unsigned int code)
	{
		auto err = std::error_code(code, std::system_category());
		throw std::system_error(err);
	}

	static void ThrowSysError(unsigned int code, const char* msg)
	{
		auto err = std::error_code(code, std::system_category());
		throw std::system_error(err, msg);
	}
}
