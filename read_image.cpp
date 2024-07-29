#include <barrier>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#define THREAD_POOL_SIZE 10

void encrypt(char buff[], char out[], unsigned long size, int thread_id,
             auto &sync_barrier) {
  std::cout << "Encrypting thread #" << thread_id << ":..." << std::endl;
  for (int i = 0; i < size; i++) out[i] = buff[i];
  std::this_thread::sleep_for(std::chrono::seconds(1));
  std::cout << "Encrypted thread #" << thread_id << std::endl;
}

int main(int argc, char *argv[]) {
  std::string filename = argv[1];
  std::filesystem::path p(filename);
  std::cout << filename << std::endl;

  unsigned long file_size = std::filesystem::file_size(p);
  std::cout << "File size: " << file_size << std::endl;
  std::fstream file_stream(filename);
  unsigned long buff_size = file_size / (THREAD_POOL_SIZE - 1);

  int total = 0;

  std::barrier sync_barrier(
      THREAD_POOL_SIZE);  // También se puede declarar una función para cuando
                          // se llegue a la barrera
  for (int i = 0; i < THREAD_POOL_SIZE; i++) {
    char buffer[buff_size];  // Probablemente haya que borrarlo despues de cada
                             // iteración
    file_stream.read(buffer, buff_size);
    std::cout << "Read " << file_stream.gcount() << " bytes" << std::endl;
    std::thread t([&]() {
      encrypt(buffer, buffer, buff_size, i, sync_barrier);
    });  // El & de la función lambda indica que el scope de la función lambda
         // es el mismo que el scope de la función main
    t.join();
    total += file_stream.gcount();
  }

  std::cout << "Total read: " << total << std::endl;

  return 0;
}