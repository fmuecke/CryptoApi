// CreateSignature.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../CryptoApi/RsaCryptoProvider.h"
#include "../CryptoApi/Conversion.h"
#include <iterator>
#include <iostream>
#include <fstream>

using namespace std;

static vector<BYTE> read_file(const char* filename)
{
	// open the file:
	ifstream file(filename, ios::binary);

	// Stop eating new lines in binary mode!!!
	file.unsetf(ios::skipws);

	// get its size:
	streampos fileSize;

	file.seekg(0, ios::end);
	fileSize = file.tellg();
	file.seekg(0, ios::beg);

	// reserve capacity
	vector<BYTE> result;
	result.reserve(fileSize);

	// read the data:
	result.insert(result.begin(), istream_iterator<BYTE>(file), istream_iterator<BYTE>());

	return std::move(result);
}

static void Usage()
{
	cerr << "usage:\n\nCreateSignature.exe <privateKey.pem> <fileToSign>\n" << endl;
}

int main(int argc, const char* argv[])
{
	try
	{
		if (argc == 0)
		{
			Usage();
			return 1;
		}

		if (argc != 3)
		{
			throw system_error(ERROR_BAD_ARGUMENTS, system_category());
		}

		CryptoApi::RsaCryptoProvider p;
		auto key = read_file(argv[1]);
		p.SetPrivateKey(string(key.begin(), key.end()));

		auto data = read_file(argv[2]);
		auto sig = p.SignData(data);
		cout << CryptoApi::Base64::Encode(sig);
	}
	catch (system_error& e)
	{
		Usage();
		cerr << "Error (" << e.code().value() << "): " << e.what() << endl;
		return e.code().value();
	}
	catch (exception &e)
	{
		Usage();
		cerr << "Error: " << e.what() << endl;
		return 1;
	}

	return 0;
}