#pragma once

#include <string>
#include <vector>

namespace CryptoApi
{
	namespace Conversion
	{
		std::string ToHexStr(const unsigned char* pData, unsigned int dataLen)
		{
			const char* NibbleToHex = { "0123456789ABCDEF" };
			if (dataLen > 0)
			{
				if (pData)
				{
					auto result = std::string(dataLen * 2, 0x00);

					for (int i = 0; i < dataLen; i++)
					{
						result[2 * i] = NibbleToHex[pData[i] >> 4];
						result[2 * i + 1] = NibbleToHex[pData[i] & 0x0F];
					}

					return result;
				}
			}
			return std::string();
		}

		// Returns 0x00 if no valid hex byte
		static unsigned char HexToVal(char c)
		{
			if (c >= '0' && c <= '9')
			{
				return c - '0';
			}
			else if (c >= 'A' && c <= 'F')
			{
				return c + 0x0A - 'A';
			}
			else if (c >= 'a' && c <= 'f')
			{
				return c + 0x0A - 'a';
			}

			return 0;
		}

		// Non-hex chars will be replaced with 0.
		static std::vector<unsigned char> FromHexStr(const char* pData, unsigned int dataLen)
		{
			if (dataLen % 2)
			{
				return std::vector<unsigned char>();
			}

			auto result = std::vector<unsigned char>();
			result.reserve(dataLen / 2);

			for (int i = 0; i < dataLen; i += 2)
			{
				auto left_nibble = HexToVal(pData[i]);
				auto right_nibble = HexToVal(pData[i + 1]);
				auto byte = (left_nibble << 4) + right_nibble;
				result.push_back(byte);
			}

			return result;
		}
	}
}