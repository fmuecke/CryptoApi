/*#include "targetver.h"
#include "CppUnitTest.h"

#include "../CryptoApi/RsaCryptor.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace CryptoApi;

namespace CryptoApiTest
{
	// generated with http://travistidwell.com/jsencrypt/demo/
	static const char* const TestPrivateKey =
		"MIICXAIBAAKBgQCJqBZROMIzrWS47vlTYZr1v+Uulq7qhsc58EVdGOQlFMREC55u"
		"V8E09gEtWf1fVHwToPn6CbmdQYUslUMa7cf2hPY0YtwAKv+TXRRXQGEH0dz0r+Vd"
		"bRhrZT/rfiGvR5OMtNreoYXM3Leiq9yVH/as4qs6H4wF+Kzck/5DTUiJPQIDAQAB"
		"AoGAAzuKQqAFl3cT7W/XNQkOvYSjGiP5uZIurYKh7ly+RsylC0AGmWrAI8E/J9R8"
		"KbfvLfrSw/dkf3fha7mZmNFKp8t/M+Q+EH4Qtq4U/JfWf/W1wDHJPZ5wzX5n7txL"
		"XeoUOYdoWZ1Um0k8S1mIdNCW6Knmz+Vym8nyWlR949YWweECQQDNgWr5amfpLCti"
		"1o2EJMZAVYhfmcme2hc/mCr2AHxyjd8QhR6S7HbODj+JbpAIQ+2mwofbdtGeXSP3"
		"F5xP/AOVAkEAq3rgdZgQVZYRg4ddedl7ljwWDy7mMqTOX6M3baS9fKvrP+J4v+Hs"
		"yghFY1XXrHQpDxV51TcZUCQX89xzbVCFCQJBAI9z6+y3blnCT3brNlYsJYf7LPsv"
		"KyMMMnZeDn8yz6xXhILPqgv9rOEh6RBScZCTem2SFawJQUI+2kA95wuebBECQAfO"
		"yHmSOuwqsRF0EGWD6YSlp7t5PzH/HwZrwBJV9eq/SS7XePgDqWxpg/9J4VAQ2e29"
		"5JY4tAZaHl0UJI1NpUECQD+xr3LYPtw0mPp/Gulx2f4CgalFCI/GAEtU/GGFMd2a"
		"Leoj6Q8pVZKllJZ7wTRJJkgQwV2/TESAU+wa8OtGDGM=";

	static const char* const TestPublicKey =
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCJqBZROMIzrWS47vlTYZr1v+Uu"
		"lq7qhsc58EVdGOQlFMREC55uV8E09gEtWf1fVHwToPn6CbmdQYUslUMa7cf2hPY0"
		"YtwAKv+TXRRXQGEH0dz0r+VdbRhrZT/rfiGvR5OMtNreoYXM3Leiq9yVH/as4qs6"
		"H4wF+Kzck/5DTUiJPQIDAQAB";

	static const char* const SampleText = "Cryptography can really be \n that \t simple!\n\nThe end...";
	static const char* const EncryptedSampleTextB64 = "AcBMBSnJ9CdvDQZzQch7edbIl1Ml4ouCDvTqSXhqGpfxth9S9eLJQ4pLtU5xHBm/Jw2V2Urhb5PKD4e60cmbj4ReX9Yz6ANlor1clLRdkODnUu0s68VnIqUz9BXyYIuOdMO8QGe4yG1qzlpr3zr4+HFmvnb7hEhKHuyAhrvn+HM=";

	TEST_CLASS(RsaCryptorTest)
	{
	public:
		TEST_METHOD(Constructor_creates_provider)
		{
			RsaCryptor c;
			Assert::IsTrue(c._provider != 0);
		}

		TEST_METHOD(Destructor_clears_provider)
		{
			RsaCryptor c;
			c.~RsaCryptor();
			Assert::IsFalse(c._provider != 0);
		}

		TEST_METHOD(Private_key_is_stored)
		{
			RsaCryptor c;
			c.ImportPrivateKeyFromText(TestPrivateKey);
			Assert::IsTrue(c._privateKey != 0);
			Assert::IsFalse(c._publicKey != 0);
			Assert::IsTrue(c._provider != 0, L"There should be a valid provider, if the key was set properly");
		}

		TEST_METHOD(Public_key_cant_be_used_as_private_key)
		{
			RsaCryptor c;
			try
			{
				c.ImportPrivateKeyFromText(TestPublicKey);
				Assert::Fail(L"Invalid private key should not be allowed");
			}
			catch (std::system_error& e)
			{
				Assert::IsTrue((e.code().value() & CRYPT_E_ASN1_ERROR) == CRYPT_E_ASN1_ERROR);
			}
		}

		TEST_METHOD(Private_key_cant_be_used_as_public_key)
		{
			RsaCryptor c;
			try
			{
				c.ImportPublicKeyFromText(TestPrivateKey);
				Assert::Fail(L"Private key should not be allowed as public key");
			}
			catch (std::system_error& e)
			{
				Assert::IsTrue((e.code().value() & CRYPT_E_ASN1_ERROR) == CRYPT_E_ASN1_ERROR);
			}
		}

		TEST_METHOD(Public_key_is_stored)
		{
			RsaCryptor c;
			c.ImportPublicKeyFromText(TestPublicKey);
			Assert::IsTrue(c._publicKey != 0);
			Assert::IsFalse(c._privateKey != 0);
			Assert::IsTrue(c._provider != 0, L"There should be a valid provider, if the key was set properly");
		}

		//TEST_METHOD(Encrypt_returns_expected_result)
		//{
		//	RsaCryptor c;
		//	c.ImportPrivateKeyFromText(TestPrivateKey);
		//	auto s = std::string(SampleText);
		//	auto encrypted = c.Encrypt(s);
		//	auto b64 = Base64::Encode(encrypted.data(), encrypted.size());

		//	auto decrypted = Base64::Decode(
		//	Assert::AreEqual(std::string(EncryptedSampleTextB64), b64);
		//}

		TEST_METHOD(Decrypt_stored_data_returns_expected_result)
		{
			RsaCryptor c;
			c.ImportPrivateKeyFromText(TestPrivateKey);
			c.ImportPublicKeyFromText(TestPublicKey);
			auto data = Base64::Decode(EncryptedSampleTextB64);
			auto decrypted = c.Decrypt(data);
			Assert::AreEqual(std::string(SampleText), decrypted);
		}

		TEST_METHOD(Can_encrypt_and_decrypt)
		{
			RsaCryptor c;
			c.ImportPrivateKeyFromText(TestPrivateKey);
			c.ImportPublicKeyFromText(TestPublicKey);

			std::string text = "Cryptography can really be \n fun!";
			auto encrypted = c.Encrypt(text);
			auto decrypted = c.Decrypt(encrypted);
			Assert::AreEqual(text, decrypted);
		}
	};
}*/