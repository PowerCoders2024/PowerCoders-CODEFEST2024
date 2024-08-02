#include <cassert>
#include <iostream>
#include <sstream>
#include "main.cpp"

void testInitializeEarthBase();
void testInitializeSatellite();

int main()
{
    // Initialize Earth and Satellite
    testInitializeEarthBase();
    testInitializeSatellite();

    return 0;
}

void testInitializeEarthBase()
{
    EarthBase earth_base;

    // Capturar la salida estándar para verificarla
    std::streambuf *originalCoutBuffer = std::cout.rdbuf();
    std::ostringstream capturedOutput;
    std::cout.rdbuf(capturedOutput.rdbuf());

    // Llamar a la función a probar
    earth_base.initializeEarthBase();

    // Restaurar el buffer de salida estándar
    std::cout.rdbuf(originalCoutBuffer);

    // Verificar la salida
    std::string output = capturedOutput.str();
    if (output.find("Client: Client Hello Communication established -->") != std::string::npos)
    {
        std::cout << "Output test passed." << std::endl;
    }
    else
    {
        std::cerr << "Output test failed." << std::endl;
    }

    // Verificar que ssl no sea nullptr
    if (earth_base.ssl != nullptr)
    {
        std::cout << "SSL initialization test passed." << std::endl;
    }
    else
    {
        std::cerr << "SSL initialization test failed." << std::endl;
    }

    // Finalizar wolfSSL
    wolfSSL_Cleanup();
}

void testInitializeSatellite()
{
    Satellite satellite;

    // Inicializar wolfSSL
    wolfSSL_Init();

    // Capturar la salida estándar para verificarla
    std::streambuf *originalCoutBuffer = std::cout.rdbuf();
    std::ostringstream capturedOutput;
    std::cout.rdbuf(capturedOutput.rdbuf());

    // Llamar a la función a probar
    int result = satellite.initializeSatellite();

    // Restaurar el buffer de salida estándar
    std::cout.rdbuf(originalCoutBuffer);

    // Verificar la salida
    std::string output = capturedOutput.str();
    if (output.find("Hint guardado en memoria correctamente") != std::string::npos)
    {
        std::cout << "Output test passed." << std::endl;
    }
    else
    {
        std::cerr << "Output test failed." << std::endl;
    }

    // Verificar que ssl no sea nullptr y la función retorne 0
    if (satellite.ssl != nullptr && result == 0)
    {
        std::cout << "SSL initialization test passed." << std::endl;
    }
    else
    {
        std::cerr << "SSL initialization test failed." << std::endl;
    }

    // Finalizar wolfSSL
    wolfSSL_Cleanup();
}