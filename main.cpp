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

// Declaraciones de funciones
void encrypt(const std::string& input_path, const std::string& output_path);
void decrypt(const std::string& input_path, const std::string& output_path);
void init_keys(byte secret[AES_128_KEY_SIZE]);
void encrypt_message(byte key[]);
void get_public_key(ecc_key& pub);

int main(int argc, char* argv[]) {
  if (argc != 4) {
    std::cerr << "Uso: " << argv[0] << " <operation> <input_path> <output_path>"
              << std::endl;
    return 1;
  }

  std::string operation = argv[1];
  std::string input_path = argv[2];
  std::string output_path = argv[3];

  if (operation == "encrypt") {
    encrypt(input_path, output_path);
  } else if (operation == "decrypt") {
    decrypt(input_path, output_path);
  } else {
    std::cerr << "Operación no válida: " << operation << std::endl;
    return 1;
  }

  return 0;
}

void encrypt(const std::string& input_path, const std::string& output_path) {
  std::cout << "input_path=" << input_path << std::endl;
  std::cout << "output_path=" << output_path << std::endl;

  byte secret[AES_128_KEY_SIZE];
  init_keys(secret);
  encrypt_message(secret);
  std::cout << "Encrypted image" << std::endl;
}

void init_keys(byte secret[AES_128_KEY_SIZE]) {
  ecc_key priv, pub;
  WC_RNG rng;

  word32 secretSz = AES_128_KEY_SIZE;
  int ret;

  wc_InitRng(&rng);    // initialize rng
  wc_ecc_init(&priv);  // initialize key
  wc_ecc_make_key(&rng, AES_128_KEY_SIZE,
                  &priv);  // make public/private key pair
  // receive public key, and initialise into pub
  get_public_key(pub);
  ret = wc_ecc_shared_secret(&priv, &pub, secret, &secretSz);
  // generate secret key

  if (ret != 0) {
    // error generating shared secret key
  }
}

void encrypt_message(byte key[]) {
  int res;
  Aes aes;
  wc_AesInit(&aes, NULL, 0);
  res = wc_AesGcmSetKey(&aes, key, 16);

  byte plain[AES_BLOCK_SIZE * 50];
  std::stringstream ss("Westcol vendiendo empanadas");
  ss.read((char*)plain, sizeof(plain));

  byte cipher[sizeof(plain)];
  byte decrypted[sizeof(plain)];
  byte iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  byte authTag[16];
  byte authIn[16] = {0};
  std::cout << "cipher size: " << sizeof(cipher) << std::endl;
  wc_AesGcmEncrypt(&aes, cipher, plain, sizeof(cipher), iv, sizeof(iv), authTag,
                   sizeof(authTag), authIn, sizeof(authIn));

  std::cout << "authIn en formato decimal Cuando sale:" << std::endl;
  for (int i = 0; i < 16; ++i) {
    std::cout << static_cast<int>(authIn[i]) << " ";
  }
  std::cout << std::endl;
  std::cout << sizeof(authTag) <<std::endl;
  std::cout << sizeof(authIn) <<std::endl;

  wc_AesGcmDecrypt(&aes, decrypted, cipher, sizeof(cipher), iv, sizeof(iv),
                   authTag, sizeof(authTag), authIn, sizeof(authIn));

  std::cout << plain << std::endl;
  std::cout << cipher << std::endl;
  std::cout << decrypted << std::endl;
}

void get_public_key(ecc_key& pub) {
  // TODO: Leer clave pública, no crearla
  WC_RNG rng;
  wc_InitRng(&rng);                 // initialize rng
  wc_ecc_init(&pub);                // initialize key
  wc_ecc_make_key(&rng, 32, &pub);  // make public key
}

void decrypt(const std::string& input_path, const std::string& output_path) {
  std::cout << "input_path=" << input_path << std::endl;
  std::cout << "output_path=" << output_path << std::endl;
  /*
   * Añada aquí su código
   */

  std::cout << "Decrypted image" << std::endl;
}
