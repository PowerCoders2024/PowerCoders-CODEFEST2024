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
void init_keys(byte secret[AES_128_KEY_SIZE]);
void get_public_key(ecc_key &pub);
void process_image_blocks(Satellite satellite, EarthBase earth_base, const std::string &input_path, const std::string &output_path, byte **cipher, size_t *cipher_size, byte **authTag,
                          size_t *authTagSz, byte **authIn, size_t *authInSz, bool encrypt);
void encrypt_block(unsigned char *block, size_t size, const unsigned char *key, const unsigned char *iv);
void decrypt_block(unsigned char *block, size_t size, const unsigned char *key, const unsigned char *iv);

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
  byte *authTag = nullptr;
  size_t authTagSz = 0;
  byte *authIn = nullptr;
  size_t authInSz = 0;

  // byte secret[AES_128_KEY_SIZE];
  // byte iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  //              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  // init_keys(secret);
  std::cout << "Encrypting image" << std::endl;
  process_image_blocks(satellite, earth_base, input_path, output_path, &cipher, &cipher_size, &authTag, &authTagSz, &authIn, &authInSz, true);
  process_image_blocks(satellite, earth_base, output_path, "deciphered.png", &cipher, &cipher_size, &authTag, &authTagSz, &authIn, &authInSz, false);
  std::cout << "Encrypted image" << std::endl;
}

void init_keys(byte secret[AES_128_KEY_SIZE])
{
  ecc_key priv, pub;
  WC_RNG rng;

  word32 secretSz = AES_128_KEY_SIZE;
  int ret;

  wc_InitRng(&rng);   // initialize rng
  wc_ecc_init(&priv); // initialize key
  wc_ecc_make_key(&rng, AES_128_KEY_SIZE,
                  &priv); // make public/private key pair
  // receive public key, and initialise into pub
  get_public_key(pub);
  ret = wc_ecc_shared_secret(&priv, &pub, secret, &secretSz);
  // generate secret key

  if (ret != 0)
  {
    // error generating shared secret key
  }
}

void encrypt_block(unsigned char *block, size_t size, const unsigned char *key, const unsigned char *iv)
{
  // int res;
  // Aes aes;
  // wc_AesInit(&aes, NULL, 0);
  // res = wc_AesGcmSetKey(&aes, key, AES_128_KEY_SIZE);

  // unsigned char tag[16];
  // wc_AesGcmEncrypt(&aes, block, block, size, iv, sizeof(iv), tag, sizeof(tag), NULL, 0);
}

void decrypt_block(unsigned char *block, size_t size, const unsigned char *key, const unsigned char *iv)
{
  int res;
  Aes aes;
  wc_AesInit(&aes, NULL, 0);
  res = wc_AesGcmSetKey(&aes, key, AES_128_KEY_SIZE);

  unsigned char tag[16];
  wc_AesGcmDecrypt(&aes, block, block, size, iv, sizeof(iv), tag, sizeof(tag), NULL, 0);
}

void get_public_key(ecc_key &pub)
{
  // TODO: Leer clave pública, no crearla
  WC_RNG rng;
  wc_InitRng(&rng);                // initialize rng
  wc_ecc_init(&pub);               // initialize key
  wc_ecc_make_key(&rng, 32, &pub); // make public key
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

  struct rusage usage;
  getrusage(RUSAGE_SELF, &usage);
  double max_memory = usage.ru_maxrss / (1024.0 * 1024.0); // Convert KB to GB
  std::cout << "Maximum memory used before: " << max_memory << " GB" << std::endl;

  auto start_time = std::chrono::high_resolution_clock::now();

  while (input_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || input_file.gcount() > 0)
  {
    size_t bytes_read = input_file.gcount();
    if (encrypt)
    {
      satellite.encryptMessage(satellite.keySession, buffer.data(), bytes_read, cipher, cipher_size, authTag, authTagSz, authIn, authInSz);
      // encrypt_block(buffer.data(), bytes_read, key, iv);
    }
    else
    {
      earth_base.decryptMessage(earth_base.keySession, *cipher, *cipher_size, *authTag, *authTagSz, *authIn, *authInSz);
      // decrypt_block(buffer.data(), bytes_read, key, iv);
    }
    output_file.write(reinterpret_cast<char *>(*cipher), bytes_read);
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;

  getrusage(RUSAGE_SELF, &usage);
  max_memory = usage.ru_maxrss / (1024.0 * 1024.0); // Convert KB to GB

  std::cout << "Time taken for block processing: " << duration.count() << " seconds" << std::endl;
  std::cout << "Maximum memory used after: " << max_memory << " GB" << std::endl;
}