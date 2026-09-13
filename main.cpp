#include <QFile>
#include <cstdio>
#include "obfuscation.h"

static constexpr std::string_view magic = "hoge";

int main()
{
	// encode
	{
		QFile file("example.input.txt");
		if (file.open(QIODevice::ReadOnly)) {
			QByteArray inputData = file.readAll();
			file.close();

			QByteArray obfuscatedData = obfuscation::encode(inputData, magic);

			QFile outputFile("example.encoded.bin");
			if (outputFile.open(QIODevice::WriteOnly)) {
				outputFile.write(obfuscatedData);
				outputFile.close();
			}
		}
	}
	
	// decode
	{
		QFile file("example.encoded.bin");
		if (file.open(QIODevice::ReadOnly)) {
			QByteArray encodedData = file.readAll();
			file.close();

			QByteArray decodedData = obfuscation::decode(encodedData, magic);

			QFile outputFile("example.decoded.txt");
			if (outputFile.open(QIODevice::WriteOnly))
			{
				outputFile.write(decodedData);
				outputFile.close();
			}
		}
	}
	
	return 0;
}