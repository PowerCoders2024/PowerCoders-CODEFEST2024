#include "EarthBase.h"
#include <wolfssl/ssl.h>

#include <iostream>
#include <string>
#include <algorithm>

EarthBase::EarthBase() : CryptoUser() {}

unsigned int EarthBase::initializeEarthBase()
{
	std::cout << "Base iniciada";
	return 1;
}

/**
 * @brief Recibe el hint del servidor.
 *
 * @param satellite Objeto Satellite para la comunicación.
 * @return unsigned int Tamaño de la clave PSK si el hint es reconocido, 0 en caso contrario.
 */
unsigned int EarthBase::receiveServerHint(Satellite &satellite)
{
	return 0;
}

/**
 * @brief Envía la identidad del cliente al servidor.
 *
 * @param satellite Objeto Satellite para la comunicación.
 * @return unsigned int 1 si la autenticación PSK fue exitosa, 0 en caso contrario.
 */
unsigned int EarthBase::sendIdentity(Satellite &satellite)
{

	return 1;
}


// Comparar dos cadenas numéricas que representan números grandes
bool isGreaterOrEqual(const std::string &a, const std::string &b) {
    if (a.size() != b.size())
        return a.size() > b.size();
    return a >= b;
}

// Resta de dos números grandes representados como cadenas
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

    // Eliminar ceros iniciales
    while (result.size() > 1 && result.back() == '0') {
        result.pop_back();
    }

    std::reverse(result.begin(), result.end());
    return result;
}

// Función para dividir dos números grandes representados como cadenas
std::string divideLargeNumber(const std::string &product, const std::string &primeStr) {
    std::string result;
    std::string current = "";

    for (char digit : product) {
        current += digit;

        // Eliminar ceros iniciales
        current.erase(0, std::min(current.find_first_not_of('0'), current.size() - 1));

        int quotient = 0;
        while (isGreaterOrEqual(current, primeStr)) {
            current = subtractLargeNumbers(current, primeStr);
            quotient++;
        }

        result.push_back(quotient + '0');
    }

    // Eliminar ceros iniciales del resultado
    result.erase(0, std::min(result.find_first_not_of('0'), result.size() - 1));

    return result.empty() ? "0" : result;
}


