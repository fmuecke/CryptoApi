#pragma once

#include "SysError.h"

#define VC_EXTRALEAN  // Exclude rarely-used stuff from Windows headers
#include <Windows.h>
#include <wincrypt.h>

#include <string>
#include <vector>
#include <iomanip>

//#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")

namespace CryptoApi
{
	namespace Hashing
	{
		// IMPORTANT: This API is DEPRECATED. 
		// New and existing software should start using Cryptography Next Generation APIs. Microsoft may remove this API in future releases.
		// see https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal

		static std::vector<unsigned char> CreateSha1(HCRYPTPROV provider, unsigned const char* pData, size_t byteLen)
		{
			HCRYPTHASH hash;
			try
			{
				if (!::CryptCreateHash(provider, CALG_SHA1, 0, 0, &hash))
					ThrowSysError();

				if (!::CryptHashData(hash, pData, static_cast<DWORD>(byteLen), 0))
					ThrowSysError();

				DWORD hashSize = 0;
				if (!::CryptGetHashParam(hash, HP_HASHSIZE, nullptr, &hashSize, 0))
					ThrowSysError();

				DWORD buffSize = 0;
				if (!::CryptGetHashParam(hash, HP_HASHVAL, nullptr, &buffSize, 0))
					ThrowSysError();

				std::vector<unsigned char> result(buffSize, 0x00);

				if (!::CryptGetHashParam(hash, HP_HASHVAL, result.data(), &buffSize, 0))
					ThrowSysError();

				if (hash) ::CryptDestroyHash(hash);

				return result;
			}
			catch (std::system_error&)
			{
				if (hash) ::CryptDestroyHash(hash);
				throw;
			}
		}



		static std::string CreateSha1(std::string const& str)
		{
			std::string retVal;

			HCRYPTPROV hCryptProv{ 0 };
			try
			{
				if (!::CryptAcquireContextA(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
					ThrowSysError();

				auto hashValue = CreateSha1(hCryptProv, reinterpret_cast<const unsigned char*>(str.data()), str.size());
				if (!hashValue.empty())
				{
					std::stringstream ss;
					ss << std::hex;
					for (auto const& c : hashValue)
					{
						if (c < 16) ss << 0;
						ss << int(c);
					}
					retVal = ss.str();
				}

				if (hCryptProv)
					::CryptReleaseContext(hCryptProv, 0);

				return retVal;
			}
			catch (std::system_error&)
			{
				if (hCryptProv)
					::CryptReleaseContext(hCryptProv, 0);

				throw;
			}
		}
	}
}
