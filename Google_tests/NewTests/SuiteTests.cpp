//
// Created by danny on 8/2/24.
//
#include "../../CipherSuite.h"
#include "gtest/gtest.h"


// Tests para EarthBase
class CipherSuiteTest : public ::testing::Test {
protected:
    CipherSuite cipherSuite;

    void SetUp() override {
        // Inicializar la base terrestre y el satélite
        cipherSuite.initializeCipherSuite();
    }
};

TEST_F(CipherSuiteTest, KeyGenerator_Success) {
    ecc_key key;
    ASSERT_EQ(1, cipherSuite.keyGenerator(key));
    wc_ecc_free(&key);
}

TEST_F(CipherSuiteTest, PerformOperation) {
    byte keyTest[32] = {
        0x6A, 0xC5, 0x3B, 0xF0, 0x8D, 0xA1, 0x7E, 0xB2,
        0x4C, 0x1F, 0x90, 0x9E, 0x3D, 0x56, 0x2A, 0xE8,
        0x7F, 0x0C, 0xA2, 0xD4, 0xE3, 0xBF, 0x68, 0x49,
        0x9A, 0x8B, 0xC0, 0x7D, 0x54, 0xB1, 0xF9, 0x6E
    };
    ecc_key key ;
    cipherSuite.keyGenerator(key);

    ASSERT_EQ(1, cipherSuite.performOperation(true,keyTest,"Google_tests/testInput.txt", "path_example_output" ));

}

TEST_F(CipherSuiteTest, ComputeBlockSizeEncryptMode) {
    // Configura los parámetros para el caso de prueba
    cipherSuite.file_size = 1000;
    cipherSuite.t_params.encrypt_mode = true;
    cipherSuite.t_params.threads_to_run = 4;

    size_t block_size = 0;
    size_t trailing_size = 0;
    cipherSuite.computeBlockSize(block_size, trailing_size);

    // Verifica los resultados esperados
    EXPECT_EQ(block_size, 250);
    EXPECT_EQ(trailing_size, 250);
}
TEST_F(CipherSuiteTest, ComputeBlockSizeNonEncryptMode) {

    cipherSuite.file_size = 1000;
    cipherSuite.t_params.encrypt_mode = false;
    cipherSuite.t_params.threads_to_run = 4;
    const size_t iv = 16;
    const size_t tagSz = 16;
    size_t blockSize = 0;
    size_t trailingSize = 0;
    cipherSuite.computeBlockSize(blockSize, trailingSize);
    size_t expectedBlockSize = (1000 - 4 * (iv + tagSz)) / 4;
    size_t expectedTrailingSize = (1000 - 4 * (iv + tagSz)) - expectedBlockSize * 3;

    EXPECT_EQ(blockSize, expectedBlockSize);
    EXPECT_EQ(trailingSize, expectedTrailingSize);
}

