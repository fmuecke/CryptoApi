#pragma once

/*#include "base64.h"

#define VC_EXTRALEAN  // Exclude rarely-used stuff from Windows headers
#include <Windows.h>
#include <wincrypt.h>

#include <string>
#include <system_error>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")

namespace CryptoApiTest
{
	class RsaCryptorTest;
}

namespace CryptoApi
{
	class RsaCryptor
	{
	public:

		RsaCryptor();
		~RsaCryptor();

		friend class CryptoApiTest::RsaCryptorTest;

		void ImportPublicKeyFromText(std::string data);
		bool ImportPrivateKeyFromText(std::string key);

	private:
		HCRYPTPROV _provider{ 0 };
		HCRYPTKEY _publicKey{ 0 };
		HCRYPTKEY _privateKey{ 0 };
	};

	inline RsaCryptor::RsaCryptor()
	{
		if (!::CryptAcquireContext(&_provider, nullptr, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			if (::GetLastError() == NTE_BAD_KEYSET)
			{
				if (!::CryptAcquireContext(&_provider, nullptr, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
				{
					// Could not create a new key container
				}
			}
			else
			{
				// A cryptographic service handle could not be acquired
			}
		}
	}

	inline RsaCryptor::~RsaCryptor()
	{
		if (_publicKey)
		{
			::CryptDestroyKey(_publicKey);
			_publicKey = 0;
		}
		if (_privateKey)
		{
			::CryptDestroyKey(_privateKey);
			_privateKey = 0;
		}
		if (_provider)
		{
			::CryptReleaseContext(_provider, 0);
			_provider = 0;
		}
	}

	inline void RsaCryptor::ImportPublicKeyFromText(std::string data)
	{
		auto key = CryptoApi::Base64::Decode(data);

		// first, parse public key struct
		DWORD blobLen{ 0 };
		if (!::CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO, key.data(), key.size(), 0, NULL, NULL, &blobLen))
		{
			auto code = ::GetLastError();
			throw std::system_error(code, std::system_category());
		}
		std::vector<unsigned char> blobData(blobLen, 0x00);
		if (!::CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO, key.data(), key.size(), 0, NULL, blobData.data(), &blobLen))
		{
			auto code = ::GetLastError();
			throw std::system_error(code, std::system_category());
		}

		// then import it
		if (!::CryptImportPublicKeyInfo(_provider, X509_ASN_ENCODING, reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(blobData.data()), &_publicKey))
		{
			auto code = ::GetLastError();
			throw std::system_error(code, std::system_category());
		}
	}

	inline bool RsaCryptor::ImportPrivateKeyFromText(std::string key)
	{
		auto buffer = CryptoApi::Base64::Decode(key);

		// first, parse private key struct
		DWORD blobLen{ 0 };
		if (!::CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, buffer.data(), buffer.size(), 0, NULL, nullptr, &blobLen))
		{
			auto code = ::GetLastError();
			throw std::system_error(code, std::system_category());
		}
		std::vector<unsigned char> blobData(blobLen, 0x00);
		if (!::CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, buffer.data(), buffer.size(), 0, NULL, blobData.data(), &blobLen))
		{
			auto code = ::GetLastError();
			throw std::system_error(code, std::system_category());
		}

		// then import it
		if (!::CryptImportKey(_provider, blobData.data(), blobData.size(), 0, CRYPT_OAEP, &_privateKey))
		{
			auto code = ::GetLastError();
			throw std::system_error(code, std::system_category());
		}

		return true;
	}
} // namespace CryptoApi
*/