#pragma once

#include "SysError.h"

//#define VC_EXTRALEAN  // Exclude rarely-used stuff from Windows headers
//#include <Windows.h>
#include <bcrypt.h>

#include <string>
#include <vector>
#include <iomanip>

#pragma comment(lib, "Bcrypt.lib")

namespace CryptoApi
{
	namespace Hashing
	{
		static std::string CreateSha1(std::string const& str)
		{
			std::string retVal;
			BCRYPT_ALG_HANDLE hAlg{ 0 };
			BCRYPT_HASH_HANDLE hHash{ 0 };

			try
			{
				// open sha1 algorithm handle
				NTSTATUS status{ -1 };
				if (!BCRYPT_SUCCESS(status = ::BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, 0)))
					ThrowSysError(status);
				
				// calculate the size of the buffer to hold the hash object
				ULONG bytesRead{ 0 };
				ULONG hashObjSize{ 0 };
				if (!BCRYPT_SUCCESS(status = ::BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<unsigned char*>(&hashObjSize), sizeof(hashObjSize), &bytesRead, 0)))
					ThrowSysError(status);

				// calculate the length of the hash (should be 20 for sha1)
				ULONG hashSize{ 0 };
				if (!BCRYPT_SUCCESS(status = ::BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<unsigned char*>(&hashSize), sizeof(hashSize), &bytesRead, 0)))
					ThrowSysError(status);

				// create the hash object
				std::vector<unsigned char> hashObj(hashObjSize, 0x00);
				if (!BCRYPT_SUCCESS(status = ::BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObj.size(), nullptr, 0, 0)))
					ThrowSysError(status);

				// hash the data
				if (!BCRYPT_SUCCESS(status = ::BCryptHashData(hHash, const_cast<PUCHAR>(reinterpret_cast<const unsigned char*>(str.data())), str.size(), 0)))
					ThrowSysError(status);

				std::vector<unsigned char> hashValue(hashSize, 0x00);
				if (!BCRYPT_SUCCESS(status = ::BCryptFinishHash(hHash, hashValue.data(), hashValue.size(), 0)))
					ThrowSysError(status);
			
				// convert to hex chars
				std::stringstream ss;
				ss << std::hex;
				for (auto const& c : hashValue)
				{
					if (c < 16) ss << 0; // padding zero
					ss << int(c);
				}
				retVal = ss.str();

				if (hHash)
					::BCryptDestroyHash(hHash);

				if (hAlg)
					::BCryptCloseAlgorithmProvider(hAlg, 0);
				
				return retVal;
			}
			catch (std::system_error&)
			{
				if (hHash)
					::BCryptDestroyHash(hHash);

				if (hAlg)
					::BCryptCloseAlgorithmProvider(hAlg, 0);

				throw;
			}
		}
	}
}
















