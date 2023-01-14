#pragma once

#define VC_EXTRALEAN		// Exclude rarely-used stuff from Windows headers
#include <Windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>

#pragma comment(lib, "Crypt32.lib")

namespace CryptoApi
{
	namespace Base64
	{
		// len: length in bytes
		static std::string Encode(const unsigned char* pData, unsigned long len)
		{
			unsigned long decodedSize{ 0 };
			if (::CryptBinaryToStringA(pData, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &decodedSize))
			{
				auto result = std::string(decodedSize, 0x00);
				//result.resize(decodedSize, 0x00);

				if (::CryptBinaryToStringA(pData, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &decodedSize))
				{
					return std::move(result);
				}
			}

			return std::move(std::string());
		}

		template<typename Container>
		static std::string Encode(Container const& data)
		{
			return Encode(data.data(), static_cast<unsigned long>(data.size()));
		}

		static std::vector<unsigned char> Decode(std::string const& base64data)
		{
			unsigned long decodedSize{ 0 };
			if (::CryptStringToBinaryA(base64data.data(), static_cast<DWORD>(base64data.size()), CRYPT_STRING_BASE64, nullptr, &decodedSize, nullptr, nullptr))
			{
				auto result = std::vector<unsigned char>(decodedSize, 0x00);
				//result.resize(decodedSize, 0x00);

				if (::CryptStringToBinaryA(base64data.data(), static_cast<DWORD>(base64data.size()), CRYPT_STRING_BASE64, &result[0], &decodedSize, nullptr, nullptr))
				{
					return result;
				}
			}

			return std::move(std::vector<unsigned char>());
		}
	}
}
