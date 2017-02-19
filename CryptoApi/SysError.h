#pragma once

#define VC_EXTRALEAN  // Exclude rarely-used stuff from Windows headers
#include <Windows.h>
#include <system_error>

namespace CryptoApi
{
	static void ThrowSysError()
	{
		auto code = ::GetLastError();
		throw std::system_error(code, std::system_category());
	}

	static void ThrowSysError(unsigned int code)
	{
		throw std::system_error(code, std::system_category());
	}
}
