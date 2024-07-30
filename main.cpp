#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include <sys/resource.h>

#include <iostream>
#include "CipherSuite.h"

#include "EarthClient/EarthBase.h"
#include "SpaceServer/Satellite.h"
#include <wolfssl/wolfcrypt/pwdbased.h>

// Variables
const size_t block_size = 1024 * 1024; // 1mb

// Declaraciones de funciones
void encrypt(const std::string &input_path, const std::string &output_path);
void decrypt(const std::string &input_path, const std::string &output_path);
void process_image_blocks(Satellite satellite, EarthBase earth_base, const std::string &input_path, const std::string &output_path, byte **cipher, size_t *cipher_size, byte **authTag,
                          size_t *authTagSz, byte **authIn, size_t *authInSz, bool encrypt);

int main(int argc, char *argv[])
{

  if (argc != 4)
  {
    std::cerr << "Uso: " << argv[0] << " <operation> <input_path> <output_path>"
              << std::endl;
    return 1;
  }

  std::string operation = argv[1];
  std::string input_path = argv[2];
  std::string output_path = argv[3];

  if (operation == "encrypt")
  {
    encrypt(input_path, output_path);
  }
  else if (operation == "decrypt")
  {
    decrypt(input_path, output_path);
  }
  else
  {
    std::cerr << "Operación no válida: " << operation << std::endl;
    return 1;
  }

  return 0;
}

void encrypt(const std::string &input_path, const std::string &output_path)
{
  std::cout << "input_path=" << input_path << std::endl;
  std::cout << "output_path=" << output_path << std::endl;

  EarthBase earth_base;
  Satellite satellite;

  // Compartir las llaves publicas entre si
  ecc_key pubEarth = earth_base.getPub();
  ecc_key pubSat = satellite.getPub();

  // Generar llave de sesion para cada uno
  earth_base.setKeySession(pubSat);
  satellite.setKeySession(pubEarth);

  // Encryptar y desencriptar
  byte *cipher = nullptr;
  size_t cipher_size = 0;

  size_t authTag_buffer_size = AES_BLOCK_SIZE;
  byte *authTag = new byte[authTag_buffer_size];
  memset(authTag, 0, authTag_buffer_size);
  size_t authTagSz = authTag_buffer_size;

  byte *authIn = nullptr;
  size_t authInSz = 0;

  std::cout << "Encrypting image" << std::endl;
  process_image_blocks(satellite, earth_base, input_path, output_path, &cipher, &cipher_size, &authTag, &authTagSz, &authIn, &authInSz, true);

  byte *clonedAuthTag = new byte[authTag_buffer_size];
  memcpy(clonedAuthTag, authTag, authTag_buffer_size);

  process_image_blocks(satellite, earth_base, output_path, "deciphered.png", &cipher, &cipher_size, &clonedAuthTag, &authTagSz, &authIn, &authInSz, false);
  std::cout << "Encrypted image" << std::endl;
}

void decrypt(const std::string &input_path, const std::string &output_path)
{
  std::cout << "input_path=" << input_path << std::endl;
  std::cout << "output_path=" << output_path << std::endl;
  /*
   * Añada aquí su código
   */

  std::cout << "Decrypted image" << std::endl;
}

void process_image_blocks(Satellite satellite, EarthBase earth_base, const std::string &input_path, const std::string &output_path, byte **cipher, size_t *cipher_size, byte **authTag,
                          size_t *authTagSz, byte **authIn, size_t *authInSz, bool encrypt)
{
  std::ifstream input_file(input_path, std::ios::binary);
  std::ofstream output_file(output_path, std::ios::binary);
  std::vector<unsigned char> buffer(block_size);

  auto start_time = std::chrono::high_resolution_clock::now();

  while (input_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || input_file.gcount() > 0)
  {
    size_t bytes_read = input_file.gcount();
    if (encrypt)
    {
      satellite.encryptMessage(satellite.keySession, buffer.data(), bytes_read, cipher, cipher_size, authTag, authTagSz, authIn, authInSz);
    }
    else
    {
      earth_base.decryptMessage(earth_base.keySession, cipher, cipher_size, authTag, authTagSz, authIn, authInSz);
    }
    output_file.write(reinterpret_cast<char *>(*cipher), bytes_read);
  }

  input_file.close();
  output_file.close();

  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;

  std::cout << "Time taken for block processing: " << duration.count() << " seconds" << std::endl;
}