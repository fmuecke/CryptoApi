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
		//
		// WARNING: requires at least Windows 10
		//
		static std::string CreateSha1(std::string const& str)
		{
			std::string retVal;
			BCRYPT_ALG_HANDLE hAlg{ 0 };

			try
			{
				// open sha1 algorithm handle
				NTSTATUS status{ -1 };
				if (!BCRYPT_SUCCESS(status = ::BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, 0)))
					ThrowSysError(status);
				
				// calculate hash
				std::vector<unsigned char> hashValue(20, 0); // SHA1
				if (!BCRYPT_SUCCESS(status = ::BCryptHash(hAlg, nullptr, 0, const_cast<PUCHAR>(reinterpret_cast<const unsigned char*>(str.data())), str.size(), hashValue.data(), hashValue.size()-2)))
					ThrowSysError(status);

				/* 
				
				USE THIS FOR SUPPORT OF WINDOWS VISTA+ instead of BCryptHash

				// calculate the size of the buffer to hold the hash object
				ULONG hashObjSize{ 0 };
				if (!BCRYPT_SUCCESS(status = ::BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, nullptr, 0, &hashObjSize, 0)))
					ThrowSysError(status);

				// calculate the length of the hash
				ULONG hashSize{ 0 };
				if (!BCRYPT_SUCCESS(status = ::BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, nullptr, 0, &hashSize, 0)))
					ThrowSysError(status);

				// create the hash
				BCRYPT_HASH_HANDLE hHash{ 0 };
				std::vector<unsigned char> hashObject(hashObjSize, 0x00);
				if (!BCRYPT_SUCCESS(status = ::BCryptCreateHash(hAlg, &hHash, hashObject.data(), hashObject.size(), nullptr, 0, 0)))
					ThrowSysError(status);

				// hash the data
				if (!BCRYPT_SUCCESS(status = ::BCryptHashData(hHash, reinterpret_cast<PUCHAR>(str.data()), str.size(), 0)))
					ThrowSysError(status);
				*/

			
				// convert to hex chars
				std::stringstream ss;
				ss << std::hex;
				for (auto const& c : hashValue)
				{
					if (c < 16) ss << 0; // padding zero
					ss << int(c);
				}
				retVal = ss.str();


				if (hAlg) 
					::BCryptCloseAlgorithmProvider(hAlg, 0);
				
				return retVal;
			}
			catch (std::system_error& err)
			{
				auto m = err.what();
				auto c = err.code();
				if (hAlg)
					::BCryptCloseAlgorithmProvider(hAlg, 0);

				throw;
			}
		}
	}
}
















