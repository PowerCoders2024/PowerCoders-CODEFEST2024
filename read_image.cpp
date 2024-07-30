
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <condition_variable>


#define THREAD_POOL_SIZE 10

void encrypt(int thread_id, uint64_t size_buff, char* buff,
             std::fstream& out_file_stream, std::mutex& mtx,
             int& mutex_counter, std::condition_variable& cv) {
  for (int i = 0; i < size_buff; i++) buff[i] = buff[i];  // Encrypt func

  while (mutex_counter != thread_id) {
    mtx.unlock();

  }

  std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, [thread_id, mutex_counter]{ return mutex_counter == thread_id; });
    out_file_stream.write(buff, size_buff);

    // Avanzar al siguiente hilo
    mutex_counter++;
    cv.notify_all();

    delete[] buff;
  
}

uint64_t open_file(std::string& filename, std::fstream& file_stream) {
  std::filesystem::path p(filename);
  std::cout << filename << std::endl;

  uint64_t file_size;
  if (std::filesystem::exists(p))
    file_size = std::filesystem::file_size(p);
  else
    file_size = 0;

  std::cout << "File size: " << file_size << std::endl;
  file_stream.open(filename);
  return file_size;
}

int main(int argc, char* argv[]) {
  std::string in_filename = argv[1];
  std::string out_filename = argv[2];
  std::fstream in_file_stream;
  std::fstream out_file_stream;

  uint64_t file_size = open_file(in_filename, in_file_stream);
  open_file(out_filename, out_file_stream);

  uint64_t buff_size = file_size / (THREAD_POOL_SIZE - 1);

  int total = 0;

  std::thread threads[THREAD_POOL_SIZE];
  
  std::condition_variable cv;
  std::mutex mtx;
  int mutex_counter = 0;
  for (int i = 0; i < THREAD_POOL_SIZE; i++) {
    

    char* buffer = new char[buff_size];

    in_file_stream.read(buffer, buff_size);
    uint64_t read = in_file_stream.gcount();

    std::thread t(encrypt, i, read, buffer, std::ref(out_file_stream),
                  std::ref(mtx), std::ref(mutex_counter), std::ref(cv));

    threads[i] = std::move(t);
    total += read;
  }

  for (int i = 0; i < THREAD_POOL_SIZE; i++) threads[i].join();

  std::cout << "Total read: " << total << std::endl;

  return 0;
}