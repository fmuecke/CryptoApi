#include "targetver.h"
#include "CppUnitTest.h"
#include <algorithm>

#include "../CryptoApi/Conversion.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace CryptoApi;

namespace CryptoApiTest
{
	TEST_CLASS(ConversionTest)
	{
	public:
		TEST_METHOD(HexToBinary__empty_results_in_empty)
		{
			Assert::IsTrue(Conversion::HexToBinary("", 0).empty());
		}

		TEST_METHOD(HexToBinary__lowercase_hex_is_valid)
		{
			auto expected = std::vector<unsigned char>{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
			auto result = Conversion::HexToBinary("0123456789abcdef", 16);
			Assert::IsTrue(std::equal(expected.begin(), expected.end(), result.begin()));
		}

		TEST_METHOD(HexToBinary__uppercase_hex_is_valid)
		{
			auto expected = std::vector<unsigned char>{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
			auto result = Conversion::HexToBinary("0123456789ABCDEF", 16);
			Assert::IsTrue(std::equal(expected.begin(), expected.end(), result.begin()));
		}

		TEST_METHOD(HexToBinary__length_not_a_multiple_of_2_results_in_empty)
		{
			Assert::IsTrue(Conversion::HexToBinary("123", 3).empty());
		}

		TEST_METHOD(HexToBinary__invalid_chars_result_in_zeroes)
		{
			auto expected = std::vector<unsigned char>{ 0x12, 0x03 };
			auto result = Conversion::HexToBinary("12z3", 4);
			Assert::IsTrue(std::equal(expected.begin(), expected.end(), result.begin()));
		}

		TEST_METHOD(BinaryToHex__empty_results_in_empty)
		{
			Assert::IsTrue(Conversion::BinaryToHex("", 0).empty());
		}

		TEST_METHOD(BinaryToHex__data_results_in_uppercase_hex)
		{
			auto expected = std::string("0001FA7364415344F6FCE4DCD6C42E");
			auto result = Conversion::BinaryToHex("\x0\x1\xfasdASDöüäÜÖÄ.", 15);
			Assert::IsTrue(expected == result);
		}
	};
}