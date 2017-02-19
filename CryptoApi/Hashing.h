#pragma once

#include "SysError.h"

#define VC_EXTRALEAN  // Exclude rarely-used stuff from Windows headers
#include <Windows.h>
#include <wincrypt.h>

#include <string>
#include <vector>

//#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")

namespace CryptoApi
{
	namespace Hashing
	{
		static std::vector<unsigned char> CreateSha1(HCRYPTPROV provider, unsigned const char* pData, size_t byteLen)
		{
			HCRYPTHASH hash;
			if (!::CryptCreateHash(provider, CALG_SHA1, 0, 0, &hash))
			{
				ThrowSysError();
			}

			if (!::CryptHashData(hash, pData, static_cast<DWORD>(byteLen), 0))
			{
				if (hash) ::CryptDestroyHash(hash);
				ThrowSysError();
			}

			DWORD hashSize = 0;
			if (!::CryptGetHashParam(hash, HP_HASHSIZE, nullptr, &hashSize, 0))
			{
				auto code = ::GetLastError();
				if (hash) ::CryptDestroyHash(hash);
				ThrowSysError(code);
			}

			DWORD buffSize = 0;
			if (!::CryptGetHashParam(hash, HP_HASHVAL, nullptr, &buffSize, 0))
			{
				auto code = ::GetLastError();
				if (hash) ::CryptDestroyHash(hash);
				ThrowSysError(code);
			}

			auto result = std::vector<unsigned char>(buffSize, 0x00);

			if (!::CryptGetHashParam(hash, HP_HASHVAL, result.data(), &buffSize, 0))
			{
				auto code = ::GetLastError();
				if (hash) ::CryptDestroyHash(hash);
				ThrowSysError(code);
			}

			if (hash) ::CryptDestroyHash(hash);

			return result;
		}
	}
}
