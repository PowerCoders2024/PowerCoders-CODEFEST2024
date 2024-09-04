#include "EarthBase.h"
#include <wolfssl/ssl.h>
#include <iostream>
#include <string>
#include <algorithm>

std::string divideLargeNumber(const std::string &product, const std::string &primeStr);
EarthBase::EarthBase() : CryptoUser() {}

unsigned int EarthBase::initializeEarthBase()
{
	std::cout << "Base iniciada";
	return 1;
}

static void intToByteArray(int value, byte arr[4]) {
    for (int i = 0; i < 4; ++i) {
        arr[i] = (value >> (i * 8)) & 0xFF;  
    }
}

/**
 * @brief Recibe el hint del servidor.
 *
 * @return unsigned int Tamaño de la clave PSK si el hint es reconocido, 0 en caso contrario.
 */
unsigned int EarthBase::receiveServerParams()
{
    byte* readLargeNumberLen = readBytes("Prueba.bin",0,1);

    size_t finalBytesLargeNumber = int((unsigned char)(readLargeNumberLen[3]) << 24 |
            (unsigned char)(readLargeNumberLen[2]) << 16 |
            (unsigned char)(readLargeNumberLen[1]) << 8 |
            (unsigned char)(readLargeNumberLen[0]));

    // Desencriptar el primo largo
    byte* iv = readBytes("Prueba.bin",0,12);
    byte* authTag = readBytes("Prueba.bin", 12,12+16);
    byte* cipheredLargeNumber = readBytes("Prueba.bin", 12+16,finalBytesLargeNumber);
    byte* serverHint = readBytes("Prueba.bin", finalBytesLargeNumber,-1);

    std::string decipherLargeNumber = decryptParams(cipheredLargeNumber,finalBytesLargeNumber -28, iv,authTag);
    std::string randomNumberStr = divideLargeNumber(decipherLargeNumber, getPrime());
    int recoveredSecret = std::stoi(randomNumberStr);
    intToByteArray(recoveredSecret, randomNumber);

	return 0;
}


std::string EarthBase::decryptParams(byte ciphertext[], size_t plaintextLen, byte iv[12], byte authTag[16]) {

    Aes aes;
    if (wc_AesGcmSetKey(&aes, pskKey, sizeof(pskKey)) != 0) {
        std::cerr << "Error al establecer la clave AES-GCM" << std::endl;
        wolfSSL_Cleanup();
    }
    byte decryptedText[plaintextLen];
    if (int pr = wc_AesGcmDecrypt(&aes, decryptedText, ciphertext, plaintextLen, iv, 12, authTag, 16, nullptr, 0) != 0) {
        std::cerr << "Error al desencriptar los datos: " << pr << std::endl;
        wolfSSL_Cleanup();

    }
    std::string decryptedString(reinterpret_cast<char*>(decryptedText), plaintextLen);

    return decryptedString;

}


byte* EarthBase::readBytes(const std::string& filename , size_t initBytes, size_t finalBytes) {

    std::ifstream inputFile(filename, std::ios::binary);
    inputFile.seekg(0, std::ios::end);
    size_t fileSize = inputFile.tellg();

    if (finalBytes == -1 ) {
        finalBytes = fileSize-4;
    }else if (finalBytes == 1) {
        finalBytes = fileSize;
        initBytes = finalBytes - 4;

    }
    size_t numBytesToRead = finalBytes - initBytes;
    byte* buffer = new byte[numBytesToRead];

    if (!inputFile) {
        std::cerr << "Error: No se pudo abrir el archivo " << filename << std::endl;
    }

    inputFile.seekg(initBytes, std::ios::beg);
    inputFile.read(reinterpret_cast<char*>(buffer), numBytesToRead);

    size_t bytesRead = inputFile.gcount();
    if (bytesRead < numBytesToRead) {
        std::cerr << "Advertencia: Solo se leyeron " << bytesRead << " bytes en lugar de " << numBytesToRead << std::endl;
    } else {
        std::cout << "Se leyeron los bytes entre " << initBytes << " y " << finalBytes << " correctamente." << std::endl;
    }

    return  buffer;
}


bool isGreaterOrEqual(const std::string &a, const std::string &b) {
    if (a.size() != b.size())
        return a.size() > b.size();
    return a >= b;
}


std::string subtractLargeNumbers(const std::string &a, const std::string &b) {
    std::string result;
    int carry = 0;
    int diff;

    for (int i = 0; i < a.size(); i++) {
        int digitA = a[a.size() - 1 - i] - '0';
        int digitB = (i < b.size() ? b[b.size() - 1 - i] - '0' : 0);
        
        diff = digitA - digitB - carry;
        if (diff < 0) {
            diff += 10;
            carry = 1;
        } else {
            carry = 0;
        }
        result.push_back(diff + '0');
    }
    
    while (result.size() > 1 && result.back() == '0') {
        result.pop_back();
    }

    std::reverse(result.begin(), result.end());
    return result;
}


std::string divideLargeNumber(const std::string &product, const std::string &primeStr) {
    std::string result;
    std::string current = "";

    for (char digit : product) {
        current += digit;

        current.erase(0, std::min(current.find_first_not_of('0'), current.size() - 1));

        int quotient = 0;
        while (isGreaterOrEqual(current, primeStr)) {
            current = subtractLargeNumbers(current, primeStr);
            quotient++;
        }

        result.push_back(quotient + '0');
    }
    
    result.erase(0, std::min(result.find_first_not_of('0'), result.size() - 1));

    return result.empty() ? "0" : result;
}



