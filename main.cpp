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

// Variables
const size_t block_size = 1024 * 1024;

// Declaraciones de funciones
void encrypt(const std::string &input_path, const std::string &output_path);
void decrypt(const std::string &input_path, const std::string &output_path);
void init_keys(byte secret[AES_128_KEY_SIZE]);
void encrypt_message(byte key[]);
void get_public_key(ecc_key &pub);
void process_image_blocks(const std::string &input_path, const std::string &output_path, const unsigned char *key, const unsigned char *iv, bool encrypt);
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

  byte secret[AES_128_KEY_SIZE];
  byte iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  init_keys(secret);
  std::cout << "Encrypting image" << std::endl;
  process_image_blocks(input_path, output_path, secret, iv, true);
  process_image_blocks(output_path, "deciphered.png", secret, iv, false);
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
  int res;
  Aes aes;
  wc_AesInit(&aes, NULL, 0);
  res = wc_AesGcmSetKey(&aes, key, AES_128_KEY_SIZE);

  // byte plain[AES_BLOCK_SIZE * 50];
  // byte cipher[sizeof(plain)];
  unsigned char tag[16];
  wc_AesGcmEncrypt(&aes, block, block, size, iv, sizeof(iv), tag, sizeof(tag), NULL, 0);
}

void decrypt_block(unsigned char *block, size_t size, const unsigned char *key, const unsigned char *iv)
{
  int res;
  Aes aes;
  wc_AesInit(&aes, NULL, 0);
  res = wc_AesGcmSetKey(&aes, key, AES_128_KEY_SIZE);

  // byte plain[AES_BLOCK_SIZE * 50];
  // byte cipher[sizeof(plain)];
  // byte decrypted[sizeof(plain)];

  unsigned char tag[16];
  wc_AesGcmDecrypt(&aes, block, block, size, iv, sizeof(iv), tag, sizeof(tag), NULL, 0);
}

void encrypt_message(byte key[])
{
  int res;
  Aes aes;
  wc_AesInit(&aes, NULL, 0);
  res = wc_AesGcmSetKey(&aes, key, 16);

  byte plain[AES_BLOCK_SIZE * 50];
  std::stringstream ss("Westcol vendiendo empanadas");
  ss.read((char *)plain, sizeof(plain));

  byte cipher[sizeof(plain)];
  byte decrypted[sizeof(plain)];
  byte iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  byte authTag[16];
  byte authIn[16] = {0};
  wc_AesGcmEncrypt(&aes, cipher, plain, sizeof(cipher), iv, sizeof(iv), authTag,
                   sizeof(authTag), authIn, sizeof(authIn));

  wc_AesGcmDecrypt(&aes, decrypted, cipher, sizeof(cipher), iv, sizeof(iv),
                   authTag, sizeof(authTag), authIn, sizeof(authIn));

  std::cout << plain << std::endl;
  std::cout << cipher << std::endl;
  std::cout << decrypted << std::endl;
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

void process_image_blocks(const std::string &input_path, const std::string &output_path, const unsigned char *key, const unsigned char *iv, bool encrypt)
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
      encrypt_block(buffer.data(), bytes_read, key, iv);
    }
    else
    {
      decrypt_block(buffer.data(), bytes_read, key, iv);
    }
    output_file.write(reinterpret_cast<char *>(buffer.data()), bytes_read);
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;

  struct rusage usage;
  getrusage(RUSAGE_SELF, &usage);
  double max_memory = usage.ru_maxrss / (1024.0 * 1024.0); // Convert KB to GB

  std::cout << "Time taken for block processing: " << duration.count() << " seconds" << std::endl;
  std::cout << "Maximum memory used: " << max_memory << " GB" << std::endl;

  // std::cout << (encrypt ? "Encrypted" : "Decrypted") << " data:\n";
  // for (unsigned char c : output_buffer)
  // {
  //   std::cout << std::hex << static_cast<int>(c);
  // }
  // std::cout << std::dec << std::endl; // Reset back to decimal formatting
}