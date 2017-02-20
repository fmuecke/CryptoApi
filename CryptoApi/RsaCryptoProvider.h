#pragma once

#include "Base64.h"
#include "SysError.h"

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
	class RsaCryptoProviderTest;
}

namespace CryptoApi
{
	class RsaCryptoProvider
	{
	public:
		RsaCryptoProvider();
		~RsaCryptoProvider();

		friend class CryptoApiTest::RsaCryptoProviderTest;

		using Byte = unsigned char;
		using Signature = std::vector<Byte>;

		// public key must be imported first
		inline std::vector<Byte> Encrypt(const char* pData, size_t dataLen) const;
		inline std::vector<Byte> Encrypt(const Byte* pData, size_t dataLen) const;

		// private key must be imported first
		inline std::string Decrypt(std::vector<Byte> const& data) const;

		// set public key from plain text (x509 or PKCS-7 encoding)
		inline void SetPublicKey(std::string const& data);
		inline void SetPublicKey(PCERT_PUBLIC_KEY_INFO pKey);

		// set privata key from plain text (x509 or PKCS-7 encoding)
		inline void SetPrivateKey(std::string const& key);
		inline void SetPrivateKey(std::vector<Byte> const& keyBlob);

		inline Signature SignData(const char* pData, size_t byteLen) const;
		inline Signature SignData(const Byte* pData, size_t byteLen) const;

		template<typename DataContainer>
		inline Signature SignData(DataContainer const& data) const
		{
			return SignData(data.data(), data.size());
		}

		inline bool VerifyData(const char* pData, size_t byteLen, Signature const& signature) const;
		inline bool VerifyData(const Byte* pData, size_t byteLen, Signature const& signature) const;

		template <typename DataContainer>
		inline bool VerifyData(DataContainer const& data, Signature const& signature) const
		{
			return VerifyData(data.data(), data.size(), signature.data(), signature.size());
		}

		//HCRYPTPROV Provider() const { return _provider; }
		//HCRYPTKEY PrivateKey() const { return _privateKey; }
		//HCRYPTKEY PublicKey() const { return _publicKey; }

	private:
		HCRYPTPROV _provider{ 0 };
		HCRYPTKEY _publicKey{ 0 };
		HCRYPTKEY _privateKey{ 0 };
	};

	//
	// function definitions
	//

	RsaCryptoProvider::RsaCryptoProvider()
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

	RsaCryptoProvider::~RsaCryptoProvider()
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

	// set public key from plain text (x509 or PKCS-7 encoding)
	inline void RsaCryptoProvider::SetPublicKey(std::string const& data)
	{
		auto key = CryptoApi::Base64::Decode(data);

		DWORD blobLen{ 0 };
		if (!::CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO, key.data(),
								   static_cast<DWORD>(key.size()), 0, NULL, NULL, &blobLen))
		{
			ThrowSysError("Public key has invalid X.509 or PKCS #7 format");
		}
		std::vector<Byte> blobData(blobLen, 0x00);
		if (!::CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO, key.data(),
								   static_cast<DWORD>(key.size()), 0, NULL, blobData.data(), &blobLen))
		{
			ThrowSysError("Public key has invalid X.509 or PKCS #7 format");
		}

		SetPublicKey(reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(blobData.data()));
	}

	inline void RsaCryptoProvider::SetPublicKey(PCERT_PUBLIC_KEY_INFO pKey)
	{
		if (!::CryptImportPublicKeyInfo(_provider, X509_ASN_ENCODING, pKey, &_publicKey))
		{
			ThrowSysError("Public key is invalid");
		}
	}

	inline void RsaCryptoProvider::SetPrivateKey(std::string const& key)
	{
		auto buffer = CryptoApi::Base64::Decode(key);

		// first, parse private key struct
		DWORD blobLen{ 0 };
		if (!::CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, buffer.data(),
								   static_cast<DWORD>(buffer.size()), 0, NULL, nullptr, &blobLen))
		{
			ThrowSysError("Private key has invalid X.509 or PKCS #7 format");
		}
		std::vector<Byte> blobData(blobLen, 0x00);
		if (!::CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, buffer.data(),
								   static_cast<DWORD>(buffer.size()), 0, NULL, blobData.data(), &blobLen))
		{
			ThrowSysError("Private key has invalid X.509 or PKCS #7 format");
		}

		SetPrivateKey(blobData);
	}

	inline void RsaCryptoProvider::SetPrivateKey(std::vector<Byte> const& keyBlob)
	{
		if (!::CryptImportKey(_provider, keyBlob.data(), static_cast<DWORD>(keyBlob.size()), 0, CRYPT_OAEP, &_privateKey))
		{
			ThrowSysError("Private key is invalid");
		}
	}

	inline RsaCryptoProvider::Signature RsaCryptoProvider::SignData(const char* pData, size_t byteLen) const
	{
		return SignData(reinterpret_cast<const Byte*>(pData), byteLen);
	}

	inline RsaCryptoProvider::Signature RsaCryptoProvider::SignData(const Byte* pData, size_t byteLen) const
	{
		if (!_privateKey)
		{
			throw std::runtime_error("Private key not set.");
		}

		HCRYPTHASH hash;
		if (!::CryptCreateHash(_provider, CALG_SHA1, 0, 0, &hash))
		{
			ThrowSysError("Creating hasher failed");
		}

		if (!::CryptHashData(hash, pData, static_cast<DWORD>(byteLen), 0))
		{
			if (hash) ::CryptDestroyHash(hash);
			ThrowSysError("Hashing the data failed");
		}

		DWORD sigSize = 0;
		if (!::CryptSignHash(hash, AT_KEYEXCHANGE, nullptr, CRYPT_NOHASHOID, nullptr, &sigSize))
		{
			auto code = ::GetLastError();
			if (hash) ::CryptDestroyHash(hash);
			ThrowSysError(code, "Signing the data hash failed");
		}

		auto result = Signature(sigSize, 0x00);

		if (!::CryptSignHash(hash, AT_KEYEXCHANGE, nullptr, CRYPT_NOHASHOID, result.data(), &sigSize))
		{
			auto code = ::GetLastError();
			if (hash) ::CryptDestroyHash(hash);
			ThrowSysError(code, "Signing the data hash failed");
		}

		if (hash) ::CryptDestroyHash(hash);

		return std::move(result);
	}

	inline bool RsaCryptoProvider::VerifyData(const char* pData, size_t byteLen, Signature const& signature) const
	{
		return VerifyData(reinterpret_cast<const Byte*>(pData), byteLen, signature);
	}

	inline bool RsaCryptoProvider::VerifyData(const Byte* pData, size_t byteLen, Signature const& signature) const
	{
		if (!_publicKey)
		{
			throw std::runtime_error("Public key not set.");
		}

		HCRYPTHASH hash;
		if (!::CryptCreateHash(_provider, CALG_SHA1, 0, 0, &hash))
		{
			ThrowSysError("Creating hasher failed");
		}

		if (!::CryptHashData(hash, pData, static_cast<DWORD>(byteLen), 0))
		{
			if (hash) ::CryptDestroyHash(hash);
			ThrowSysError("Hashing the data failed");
		}

		bool result = false;
		if (::CryptVerifySignature(hash, signature.data(), static_cast<DWORD>(signature.size()), _publicKey, nullptr, CRYPT_NOHASHOID))
		{
			result = true;
		}

		if (hash) ::CryptDestroyHash(hash);

		return result;
	}

	inline std::vector<RsaCryptoProvider::Byte> RsaCryptoProvider::Encrypt(const char* pData, size_t dataLen) const
	{
		return Encrypt(reinterpret_cast<const Byte*>(pData), dataLen);
	}

	inline std::vector<RsaCryptoProvider::Byte> RsaCryptoProvider::Encrypt(const Byte* pData, size_t dataLen) const
	{
		if (!_publicKey)
		{
			return std::vector<Byte>();
		}

		unsigned long length = dataLen;
		auto buffer = std::vector<Byte>(length, 0);
		std::copy(pData, pData + dataLen, std::begin(buffer));

		if (!::CryptEncrypt(_publicKey, 0, true, 0, buffer.data(), &length, buffer.size()))
		{
			auto errorCode = ::GetLastError();
			if (errorCode != ERROR_MORE_DATA)
			{
				throw std::system_error(errorCode, std::system_category());
			}

			buffer.resize(length, 0x00);
			length = dataLen;
			if (!::CryptEncrypt(_publicKey, 0, true, 0, buffer.data(), &length, buffer.size()))
			{
				ThrowSysError("Encryption failed");
			}
		}

		return std::move(buffer);
	}

	inline std::string RsaCryptoProvider::Decrypt(std::vector<RsaCryptoProvider::Byte> const& data) const
	{
		if (!_privateKey)
		{
			return std::string();
		}

		unsigned long length = data.size();
		auto buffer = std::vector<unsigned char>(length, 0);
		std::copy(std::begin(data), std::end(data), std::begin(buffer));

		if (!::CryptDecrypt(_privateKey, 0, true, 0, buffer.data(), &length))
		{
			auto errorCode = ::GetLastError();
			if (errorCode != ERROR_MORE_DATA)
			{
				throw std::system_error(errorCode, std::system_category());
			}

			//buffer.resize(length, 0x00);
			if (!::CryptDecrypt(_privateKey, 0, true, 0, buffer.data(), &length))
			{
				ThrowSysError("Decryption failed");
			}
		}

		return std::move(std::string(std::begin(buffer), std::begin(buffer) + length));
	}
}
