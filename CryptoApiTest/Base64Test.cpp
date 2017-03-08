#include "targetver.h"
#include "CppUnitTest.h"

#include "../CryptoApi/Base64.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace CryptoApi;
using namespace std;

namespace CryptoApiTest
{
#pragma warning(suppress: 26490)
	static const unsigned char* bytePtr(std::string const& s) { return reinterpret_cast<const unsigned char*>(s.data()); }

	TEST_CLASS(Base64Test)
	{
		TEST_METHOD(Encode_nullptr_returns_empty)
		{
			Assert::IsTrue(Base64::Encode(nullptr, 0).empty(), L"encoding a null string should return empty");
		}

		TEST_METHOD(Encode_empty_returns_empty)
		{
			string s;
			Assert::IsTrue(Base64::Encode(bytePtr(s), s.size()).empty(), L"encoding an empty string should return empty");
		}

		TEST_METHOD(Encode_one_whitespace_returns_X)
		{
			string s = " ";
			auto result = Base64::Encode(bytePtr(s), s.size());
			Assert::AreEqual("IA==", result.c_str());
		}

		TEST_METHOD(Encode_two_whitespaces_returns_X)
		{
			string s = "  ";
			auto result = Base64::Encode(bytePtr(s), s.size());
			Assert::AreEqual("ICA=", result.c_str());
		}

		TEST_METHOD(Encode_three_whitespaces_returns_X)
		{
			string s = "   ";
			auto result = Base64::Encode(bytePtr(s), s.size());
			Assert::AreEqual("ICAg", result.c_str());
		}

		TEST_METHOD(Encode_string_returns_expected_value)
		{
			string s = "Hallo Welt!";
			auto result = Base64::Encode(bytePtr(s), s.size());
			Assert::AreEqual("SGFsbG8gV2VsdCE=", result.c_str());
		}

		TEST_METHOD(Decode_string_returns_expected_value)
		{
			string s = "SGFsbG8gV2VsdCE=";
			auto result = Base64::Decode(s);
			Assert::AreEqual("Hallo Welt!", string(begin(result), end(result)).c_str());
		}
	};
}