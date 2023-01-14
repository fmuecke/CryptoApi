#include "targetver.h"
#include "CppUnitTest.h"
//#include <algorithm>

#include "../CryptoApi/Hashing.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace CryptoApi;

namespace CryptoApiTest
{
	TEST_CLASS(HashingTest)
	{
	public:
		TEST_METHOD(sha1_is_40_chars_long)
		{
			auto hash = Hashing::CreateSha1("");
			Assert::AreEqual("da39a3ee5e6b4b0d3255bfef95601890afd80709", hash.c_str());
		}

		TEST_METHOD(sha1_of_empty_string_is_correct)
		{
			auto hash = Hashing::CreateSha1("");
			Assert::AreEqual("da39a3ee5e6b4b0d3255bfef95601890afd80709", hash.c_str());
		}

		TEST_METHOD(sha1_of_test_string_is_correct)
		{
			auto hash = Hashing::CreateSha1("Hello hashing world!");
			Assert::AreEqual("b74cfde54e1c84f6cadfbe5364ef2a9c53c5b029", hash.c_str());
		}

		TEST_METHOD(sha1_of_string_array_is_correct)
		{
			std::string str{ 0x00, 'S', 0x00, 'H', 0x00, '1' };
			auto hash = Hashing::CreateSha1(str);
			Assert::AreEqual("ecb3c5ee01e22ba99e25fe5e2ceaeb3db8c96cf3", hash.c_str());
		}
	};
}