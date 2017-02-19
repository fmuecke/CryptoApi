//-------------------------------------------------------------------
// Example C Program:
// Signs a message by using a sender's private key and encrypts the
// signed message by using a receiver's public key.
#pragma once
#pragma comment(lib, "crypt32.lib")

//#include <stdio.h>
//#include <tchar.h>
#include <windows.h>
#include <Wincrypt.h>
#include <vector>
#include <system_error>
#include <string>

class MessageSigner
{
	//-------------------------------------------------------------------
	// Define the name of a certificate subject.
	// To use this program, the definition of SIGNER_NAME must be changed to the name of the subject of
	// a certificate that has access to a private key. That certificate must have either the
	// CERT_KEY_PROV_INFO_PROP_ID or CERT_KEY_CONTEXT_PROP_ID property set for the context to provide
	// access to the private signature key.

	//-------------------------------------------------------------------
	// You can use a command similar to the following to create a
	// certificate that can be used with this example:
	//
	//   makecert -n "cn=Test" -sk Test -ss my

public:
	MessageSigner(std::wstring signerName, std::wstring storeName)
		: _signer{ signerName }, _store{ storeName }
	{}

	std::vector<BYTE> Sign(std::vector<BYTE> const& data)
	{
		// Open the certificate store.
		HCERTSTORE hCertStore = 0;
		PCCERT_CONTEXT pSignerCert;

		auto result = std::vector<BYTE>();
		try
		{
			if (!(hCertStore = ::CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, _store.c_str())))
			{
				ThrowError("The MY store could not be opened.");
			}

			// Get a pointer to the signer's certificate.
			// This certificate must have access to the signer's private key.
			if (!(pSignerCert = ::CertFindCertificateInStore(hCertStore, DefaultEncodingType, 0, CERT_FIND_SUBJECT_STR, _signer.c_str(), NULL)))
			{
				ThrowError("Signer certificate not found.");
			}

			// Initialize the signature structure.
			CRYPT_SIGN_MESSAGE_PARA signParams;
			signParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
			signParams.dwMsgEncodingType = DefaultEncodingType;
			signParams.pSigningCert = pSignerCert;
			signParams.HashAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
			signParams.HashAlgorithm.Parameters.cbData = NULL;
			signParams.cMsgCert = 1;
			signParams.rgpMsgCert = &pSignerCert;
			signParams.cAuthAttr = 0;
			signParams.dwInnerContentType = 0;
			signParams.cMsgCrl = 0;
			signParams.cUnauthAttr = 0;
			signParams.dwFlags = 0;
			signParams.pvHashAuxInfo = NULL;
			signParams.rgAuthAttr = NULL;

			const BYTE* dataArray[] = { data.data() };
			DWORD dataSizeArray[] = { static_cast<DWORD>(data.size()) };

			// First get the size, then sign the data.
			DWORD requiredBytes = 0;
			if (!::CryptSignMessage(&signParams, FALSE, 1, dataArray, dataSizeArray, NULL, &requiredBytes))
			{
				ThrowError("Getting signed BLOB size failed");
			}
			result.resize(requiredBytes, 0x00);

			if (!::CryptSignMessage(&signParams, FALSE, 1, dataArray, dataSizeArray, result.data(), &requiredBytes))
			{
				ThrowError("Error getting signed BLOB");
			}
		}
		catch (std::exception& e)
		{
			if (pSignerCert) ::CertFreeCertificateContext(pSignerCert);
			if (hCertStore) ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
			throw;
		}

		if (pSignerCert) ::CertFreeCertificateContext(pSignerCert);
		if (hCertStore) ::CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);

		return result;
	}

	// Verify the message signature. Usually, this would be done in a separate program.
	std::vector<BYTE> Verify(std::vector<BYTE> const& signedData)
	{
		// Initialize the VerifyParams data structure.
		CRYPT_VERIFY_MESSAGE_PARA verifyParams;
		verifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
		verifyParams.dwMsgAndCertEncodingType = DefaultEncodingType;
		verifyParams.hCryptProv = 0;
		verifyParams.pfnGetSignerCertificate = nullptr;
		verifyParams.pvGetArg = nullptr;

		// First, call CryptVerifyMessageSignature to get the length of the buffer needed to hold the decoded message.
		DWORD requiredBytes = 0;
		if (!::CryptVerifyMessageSignature(&verifyParams, 0, signedData.data(), signedData.size(), nullptr, &requiredBytes, nullptr))
		{
			ThrowError("Verification message failed.");
		}

		std::vector<BYTE> result(requiredBytes, 0x00);

		//---------------------------------------------------------------
		// Call CryptVerifyMessageSignature again to verify the signature and, if successful, copy the decoded message into the buffer.
		// This will validate the signature against the certificate in the local store.
		if (!::CryptVerifyMessageSignature(&verifyParams, 0, signedData.data(), signedData.size(), result.data(), &requiredBytes, nullptr))
		{
			result.clear();
		}

		return result;
	}

private:
	static void ThrowError(const char* msg)
	{
		auto code = ::GetLastError();
		throw std::system_error(code, std::system_category(), msg);
	}

	static void ThrowError()
	{
		auto code = ::GetLastError();
		throw std::system_error(code, std::system_category());
	}

	static const DWORD DefaultEncodingType{ (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING) };

	std::wstring _signer;
	std::wstring _store;
};