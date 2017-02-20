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
	// generated with http://travistidwell.com/jsencrypt/demo/
	// or via openssl
	//    openssl genrsa -out rsa_1024_priv.pem 1024
	//    openssl rsa -pubout -in rsa_1024_priv.pem -out rsa_1024_pub.pem

	static const char* const PrivateKey =
		"MIICXwIBAAKBgQC81ttq65As+LUndLlVr2lWhb/GWjdAGgf8i9NUO5dJNeokXVMB"
		"X71Y6R5Vm3+w0pgI6ffnlbHCcSyohxg9a6ud6CWlKw/XtXiaJNmL/2lfj81nep5W"
		"sYtReoV7AncK+q98YMJOrgKMd56PHwjonqrS+s+0IZmi+HZHZaBahwelmQIDAQAB"
		"AoGBAIGDirFmJlfxq60H7STLTZ+9062iqkoYkGmxLJuU00mu5ItURl2m4CJeoCNu"
		"psELbqKOdSwsCuKk5FAhd4qIkgZnSGyKJ40bv0RLNe88anezULt9yPi0IVfjL1wK"
		"J6xgtorH7+ZShxVwwW/oIRpZXpp/wPUITwissZhXOVauuc4BAkEA90APq88HCqqC"
		"xV5xz5n6+oKJDsjlfThwrVRIhEKxSezvcp0hMsOSEq9OEKhn93Lknek+EptPUZyX"
		"gCCLYBxp8QJBAMOFoLDqy3/taokXNmxDd0blxQcinPB3t2GNVOKPcM/XMZs6CHJx"
		"tqom/2PNou0ESQtMc3/yFljmjY88y/wnjikCQQDoRsZyIYv7+TPhN1i0L3QY44je"
		"2ty9RsiUDRoTJpRnXq+UfQkzJ4eTBh3QiGUjkkw0DWrDECT0BqhNNkW5hPgBAkEA"
		"tCL9NYJdEvPN35g/T+eokO1IZZaCORpTHdF0j3fQW+zLi1QgTDBwNrvPOEhQ/0Wf"
		"doVtNEf6RtXDPmCpHxviYQJBAKPBcusnPfO9JSKqOkH2C0mAjiMyxAR0BbSBAgFf"
		"9qWkZi6S/pULWn2rlBDCheiMpbUBABMZMqRW5ifUEJKh2HM=";

	static const char* const PublicKey =
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC81ttq65As+LUndLlVr2lWhb/G"
		"WjdAGgf8i9NUO5dJNeokXVMBX71Y6R5Vm3+w0pgI6ffnlbHCcSyohxg9a6ud6CWl"
		"Kw/XtXiaJNmL/2lfj81nep5WsYtReoV7AncK+q98YMJOrgKMd56PHwjonqrS+s+0"
		"IZmi+HZHZaBahwelmQIDAQAB";

	static const char* const PublicKeyWithHeader =
		"-----BEGIN PUBLIC KEY-----"
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC81ttq65As+LUndLlVr2lWhb/G"
		"WjdAGgf8i9NUO5dJNeokXVMBX71Y6R5Vm3+w0pgI6ffnlbHCcSyohxg9a6ud6CWl"
		"Kw/XtXiaJNmL/2lfj81nep5WsYtReoV7AncK+q98YMJOrgKMd56PHwjonqrS+s+0"
		"IZmi+HZHZaBahwelmQIDAQAB"
		"-----END PUBLIC KEY-----";

	static const char* const WrongPublicKey =
		"AAAAB3NzaC1yc2EAAAABJQAAAIEApSVaPhBPsu2NzoJDfjx6HIf6pGBjRz0UXIEv"
		"0QPdMqLDl0BX7f54BwSYjUf56DWvF07MogZ0R9tsS8QXZXZ1ZcOCbdPbElzddLqx"
		"6qLObwE5wFvx87PnKwooS856qXMVfZTzQOQMV5eejUVdkjaRLXvkNWO8RzmWFDRa"
		"O0eD2BM=";

	static const char* const SampleText = "Cryptography can really be \n that \t simple!\n\nThe end...";
	static const char* const EncryptedSampleTextB64 = "0i3OP0Q5aq7lkUhPrRA9Ae5x8NyV+0v56vlXKrwdjWs+X0ADD3GZcaVW2znrgJ/5Od/zYxcfNhEaAnarKrXchJ9Z1yDhB3fy60w9m1yBKwIiWsQxRasMWgwuT/UAHcfdN/G+8NUc96KaQzICaS580INXHlHRWedsa435CUfJBa4=";

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

			p.SetPublicKey(PublicKeyWithHeader);
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

		TEST_METHOD(Public_key_can_be_set)
		{
			RsaCryptoProvider c;
			c.SetPublicKey(PublicKey);
			Assert::IsTrue(c._publicKey != 0);
			Assert::IsFalse(c._privateKey != 0);
			Assert::IsTrue(c._provider != 0, L"There should be a valid provider, if the key was set properly");
		}

		TEST_METHOD(Encrypt_returns_differnt_result_each_time)
		{
			RsaCryptoProvider c;
			c.SetPublicKey(PublicKey);
			auto s = std::string(SampleText);
			auto encrypted1 = c.Encrypt(s.c_str(), s.size());
			auto encrypted2 = c.Encrypt(s.c_str(), s.size());
			Assert::IsFalse(std::equal(encrypted1.begin(), encrypted1.end(), encrypted2.begin()));
		}

		TEST_METHOD(Decrypt_stored_data_returns_expected_result)
		{
			RsaCryptoProvider c;
			c.SetPrivateKey(PrivateKey);
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