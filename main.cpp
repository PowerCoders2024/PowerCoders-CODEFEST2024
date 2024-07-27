#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

// Declaraciones de funciones
void encrypt(const std::string& input_path, const std::string& output_path);
void decrypt(const std::string& input_path, const std::string& output_path);
void init_keys(byte secret[]);
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

  byte secret[1024];
  init_keys(secret);
  std::cout << "Encrypted image" << std::endl;
}

void init_keys(byte secret[]) {
  ecc_key priv, pub;
  WC_RNG rng;

  word32 secretSz = sizeof(secret);
  int ret;

  wc_InitRng(&rng);                  // initialize rng
  wc_ecc_init(&priv);                // initialize key
  wc_ecc_make_key(&rng, 32, &priv);  // make public/private key pair
  // receive public key, and initialise into pub
  get_public_key(pub);
  ret = wc_ecc_shared_secret(&priv, &pub, secret, &secretSz);
  // generate secret key

  if (ret != 0) {
    // error generating shared secret key
  }
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
