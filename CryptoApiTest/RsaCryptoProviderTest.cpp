#include "targetver.h"
#include "CppUnitTest.h"

#include "../CryptoApi/Base64.h"
#include "../CryptoApi/RsaCryptoProvider.h"

#include <iostream>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace CryptoApi;
using namespace std;

namespace CryptoApiTest
{
	static const char* const PrivateKey =
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

	static const char* const PublicKey =
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCJqBZROMIzrWS47vlTYZr1v+Uu"
		"lq7qhsc58EVdGOQlFMREC55uV8E09gEtWf1fVHwToPn6CbmdQYUslUMa7cf2hPY0"
		"YtwAKv+TXRRXQGEH0dz0r+VdbRhrZT/rfiGvR5OMtNreoYXM3Leiq9yVH/as4qs6"
		"H4wF+Kzck/5DTUiJPQIDAQAB";

	static const char* const WrongPublicKey =
		"AAAAB3NzaC1yc2EAAAABJQAAAIEApSVaPhBPsu2NzoJDfjx6HIf6pGBjRz0UXIEv"
		"0QPdMqLDl0BX7f54BwSYjUf56DWvF07MogZ0R9tsS8QXZXZ1ZcOCbdPbElzddLqx"
		"6qLObwE5wFvx87PnKwooS856qXMVfZTzQOQMV5eejUVdkjaRLXvkNWO8RzmWFDRa"
		"O0eD2BM=";

	static const char* const SampleText = "Cryptography can really be \n that \t simple!\n\nThe end...";
	static const char* const EncryptedSampleTextB64 = "AcBMBSnJ9CdvDQZzQch7edbIl1Ml4ouCDvTqSXhqGpfxth9S9eLJQ4pLtU5xHBm/Jw2V2Urhb5PKD4e60cmbj4ReX9Yz6ANlor1clLRdkODnUu0s68VnIqUz9BXyYIuOdMO8QGe4yG1qzlpr3zr4+HFmvnb7hEhKHuyAhrvn+HM=";

	TEST_CLASS(RsaCryptoProviderTest)
	{
		TEST_METHOD(Valid_data_produces_non_empty_signature)
		{
			RsaCryptoProvider p;
			p.SetPrivateKey(PrivateKey);

			Assert::IsFalse(p.SignData("Hallo Welt!", 11).empty());
		}

		TEST_METHOD(Valid_signature_passes_verification)
		{
			RsaCryptoProvider p;
			p.SetPrivateKey(PrivateKey);
			p.SetPublicKey(PublicKey);

			Assert::IsTrue(p.VerifyData("Hallo Welt!", 11, p.SignData("Hallo Welt!", 11)));
		}

		TEST_METHOD(Modified_data_fails_verification)
		{
			RsaCryptoProvider p;
			p.SetPrivateKey(PrivateKey);
			p.SetPublicKey(PublicKey);

			Assert::IsFalse(p.VerifyData("Hallö Welt!", 11, p.SignData("Hallo Welt!", 11)));
		}

		TEST_METHOD(Constructor_creates_provider)
		{
			RsaCryptoProvider c;
			Assert::IsTrue(c._provider != 0);
		}

		TEST_METHOD(Destructor_clears_provider)
		{
			RsaCryptoProvider c;
			c.~RsaCryptoProvider();
			Assert::IsFalse(c._provider != 0);
		}

		TEST_METHOD(Private_key_is_stored)
		{
			RsaCryptoProvider c;
			c.SetPrivateKey(PrivateKey);
			Assert::IsTrue(c._privateKey != 0);
			Assert::IsFalse(c._publicKey != 0);
			Assert::IsTrue(c._provider != 0, L"There should be a valid provider, if the key was set properly");
		}

		TEST_METHOD(Public_key_cant_be_used_as_private_key)
		{
			RsaCryptoProvider c;
			try
			{
				c.SetPrivateKey(PublicKey);
				Assert::Fail(L"Invalid private key should not be allowed");
			}
			catch (std::system_error& e)
			{
				Assert::IsTrue((e.code().value() & CRYPT_E_ASN1_ERROR) == CRYPT_E_ASN1_ERROR);
			}
		}

		TEST_METHOD(Private_key_cant_be_used_as_public_key)
		{
			RsaCryptoProvider c;
			try
			{
				c.SetPublicKey(PrivateKey);
				Assert::Fail(L"Private key should not be allowed as public key");
			}
			catch (std::system_error& e)
			{
				Assert::IsTrue((e.code().value() & CRYPT_E_ASN1_ERROR) == CRYPT_E_ASN1_ERROR);
			}
		}

		TEST_METHOD(Public_key_is_stored)
		{
			RsaCryptoProvider c;
			c.SetPublicKey(PublicKey);
			Assert::IsTrue(c._publicKey != 0);
			Assert::IsFalse(c._privateKey != 0);
			Assert::IsTrue(c._provider != 0, L"There should be a valid provider, if the key was set properly");
		}

		//TEST_METHOD(Encrypt_returns_expected_result)
		//{
		//	RsaCryptoProvider c;
		//	c.ImportPrivateKeyFromText(TestPrivateKey);
		//	auto s = std::string(SampleText);
		//	auto encrypted = c.Encrypt(s);
		//	auto b64 = Base64::Encode(encrypted.data(), encrypted.size());

		//	auto decrypted = Base64::Decode(
		//	Assert::AreEqual(std::string(EncryptedSampleTextB64), b64);
		//}

		TEST_METHOD(Decrypt_stored_data_returns_expected_result)
		{
			RsaCryptoProvider c;
			c.SetPrivateKey(PrivateKey);
			c.SetPublicKey(PublicKey);
			auto data = Base64::Decode(EncryptedSampleTextB64);
			auto decrypted = c.Decrypt(data);
			Assert::AreEqual(std::string(SampleText), decrypted);
		}

		TEST_METHOD(Can_encrypt_and_decrypt)
		{
			RsaCryptoProvider c;
			c.SetPrivateKey(PrivateKey);
			c.SetPublicKey(PublicKey);

			std::string text = "Cryptography can really be \n fun!";
			auto encrypted = c.Encrypt(text.c_str(), text.size());
			auto decrypted = c.Decrypt(encrypted);
			Assert::AreEqual(text, decrypted);
		}
	};
}

// http://stackoverflow.com/questions/25814546/verify-openpgp-based-rsa-signature-with-wincrypt-cryptoapi
/*
I have code that parses OpenPGP packets and I have n, e of the public key packet as well as s of the signature packet as byte arrays.

In order to verify a signature I first initialize CryptAcquireContext (I also tried with PROV_RSA_FULL instead of PROV_RSA_AES)

	HCRYPTPROV hCryptProv;
	CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

then create a hash

	HCRYPTHASH hHash;
	CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash); // as the digest algorithm of the signature was 2 => SHA1

and populate it using CryptHashData. This works so far as well as parsing and importing the public key using CryptImportKey.

*/

//typedef struct _RSAKEY
//{
//	BLOBHEADER blobheader;
//	RSAPUBKEY rsapubkey;
//	BYTE n[4096 / 8];
//} RSAKEY;
//
//static int verify_signature_rsa(HCRYPTPROV hCryptProv, HCRYPTHASH hHash, public_key_t &p_pkey, signature_packet_t &p_sig)
//{
//	int i_n_len = mpi_len(p_pkey.key.sig.rsa.n); // = 512; p_pkey.key.sig.rsa.n is of type uint8_t n[2 + 4096 / 8];
//	int i_s_len = mpi_len(p_sig.algo_specific.rsa.s); // = 256; p_sig.algo_specific.rsa.s is of type uint8_t s[2 + 4096 / 8]
//
//	HCRYPTKEY hPubKey;
//	RSAKEY rsakey;
//	rsakey.blobheader.bType = PUBLICKEYBLOB; // 0x06
//	rsakey.blobheader.bVersion = CUR_BLOB_VERSION; // 0x02
//	rsakey.blobheader.reserved = 0;
//	rsakey.blobheader.aiKeyAlg = CALG_RSA_KEYX;
//	rsakey.rsapubkey.magic = 0x31415352;// ASCII for RSA1
//	rsakey.rsapubkey.bitlen = i_n_len * 8; // = 4096
//	rsakey.rsapubkey.pubexp = 65537;
//
//	memcpy(rsakey.n, p_pkey.key.sig.rsa.n + 2, i_n_len); // skip first two byte which are MPI length
//	std::reverse(rsakey.n, rsakey.n + i_n_len); // need to convert to little endian for WinCrypt
//
//	CryptImportKey(hCryptProv, (BYTE*)&rsakey, sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + i_n_len, 0, 0, &hPubKey); // no error
//
//	std::unique_ptr<BYTE[]> pSig(new BYTE[i_s_len]);
//	memcpy(pSig.get(), p_sig.algo_specific.rsa.s + 2, i_s_len); // skip first two byte which are MPI length
//	//BAD:std::reverse(p_sig.algo_specific.rsa.s, p_sig.algo_specific.rsa.s + i_s_len); // need to convert to little endian for WinCrypt
//	std::reverse(pSig.get(), pSig.get() + i_s_len); // need to convert to little endian for WinCrypt
//
//	if (!CryptVerifySignature(hHash, pSig.get(), i_s_len, hPubKey, nullptr, 0))
//	{
//		DWORD err = GetLastError(); // err=2148073478 -> INVALID_SIGNATURE
//		CryptDestroyKey(hPubKey);
//		return -1;
//	}
//
//	CryptDestroyKey(hPubKey);
//	return 0;
//}