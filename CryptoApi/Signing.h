#pragma once

#include "RsaCryptoProvider.h"
#include "SysError.h"
#include "Hashing.h"

#define VC_EXTRALEAN  // Exclude rarely-used stuff from Windows headers
#include <Windows.h>
#include <wincrypt.h>

#include <string>
#include <vector>

//#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")

//namespace CryptoApiTest
//{
//	class RsaCryptorTest;
//}

namespace CryptoApi
{
	namespace Signing
	{
		/*template<typename DataContainer>
		static std::vector<unsigned char> SignData(std::string const& privateKey, DataContainer const& data)
		{
			return SignData(privateKey, data.data(), data.size());
		}

		static std::vector<unsigned char> SignData(std::string const& privateKey, unsigned const char* pData, size_t byteLen)
		{
			RsaCryptoProvider provider;
			provider.SetPrivateKey(privateKey);

			HCRYPTHASH hash;
			if (!::CryptCreateHash(_provider.Provider(), CALG_SHA1, 0, 0, &hash))
			{
				ThrowSysError();
			}

			if (!::CryptHashData(hash, pData, static_cast<DWORD>(byteLen), 0))
			{
				if (hash) ::CryptDestroyHash(hash);
				ThrowSysError();
			}

			DWORD sigSize = 0;
			if (!::CryptSignHash(hash, AT_KEYEXCHANGE, nullptr, CRYPT_NOHASHOID, nullptr, &sigSize))
			{
				auto code = ::GetLastError();
				if (hash) ::CryptDestroyHash(hash);
				ThrowSysError(code);
			}

			auto result = std::vector<unsigned char>(sigSize, 0x00);

			if (!::CryptSignHash(hash, AT_KEYEXCHANGE, nullptr, CRYPT_NOHASHOID, result.data(), &sigSize))
			{
				auto code = ::GetLastError();
				if (hash) ::CryptDestroyHash(hash);
				ThrowSysError(code);
			}

			if (hash) ::CryptDestroyHash(hash);

			return std::move(result);
		}

		template <typename DataContainer, typename SignatureContainer>
		static bool VerifyData(std::string const& publicKey, DataContainer const& data, SignatureContainer const& signature)
		{
			return VerifyData(publicKey, data.data(), data.size(), signature.data(), signature.size());
		}

		static bool VerifyData(std::string const& publicKey, unsigned const char* pData, size_t byteLen, unsigned const char* pSignature, size_t signatureLen)
		{
			RsaCryptoProvider provider;
			provider.SetPublicKey(publicKey);

			HCRYPTHASH hash;
			if (!::CryptCreateHash(provider.Provider(), CALG_SHA1, 0, 0, &hash))
			{
				ThrowSysError();
			}

			if (!::CryptHashData(hash, pData, static_cast<DWORD>(byteLen), 0))
			{
				if (hash) ::CryptDestroyHash(hash);
				ThrowSysError();
			}

			bool result = false;
			if (::CryptVerifySignature(hash, pSignature, static_cast<DWORD>(signatureLen), provider.PublicKey(), nullptr, CRYPT_NOHASHOID))
			{
				result = true;
			}

			if (hash) ::CryptDestroyHash(hash);

			return result;
		}*/
	}
} // namespace CryptoApi
