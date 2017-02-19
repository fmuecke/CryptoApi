#include "targetver.h"
#include "CppUnitTest.h"

#include "../CryptoApi/Conversion.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace CryptoApi;

namespace CryptoApiTest
{
	TEST_CLASS(StringManipulationTest)
	{
	public:
		TEST_METHOD(empty)
		{
			auto result = Conversion::ToHexStr(reinterpret_cast<unsigned char*>("12345"), 5);

			auto result2 = Conversion::FromHexStr(result.data(), result.size());
		}
	};
}