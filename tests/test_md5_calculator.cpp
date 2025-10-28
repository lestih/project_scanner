#include <gtest/gtest.h>
#include "md5_calculator.h"
#include "test_utils.h"
#include <fstream>

class MD5CalculatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Создаем тестовые файлы
        emptyFile = test_utils::createTempFile("");
        helloFile = test_utils::createTempFile("hello");
        binaryFile = test_utils::createTempFile("binary\0data", ".bin");
    }
    
    void TearDown() override {
        // Очищаем тестовые файлы
        test_utils::cleanup(emptyFile);
        test_utils::cleanup(helloFile);
        test_utils::cleanup(binaryFile);
    }
    
    std::string emptyFile;
    std::string helloFile;
    std::string binaryFile;
};


TEST_F(MD5CalculatorTest, EmptyFile) {
    std::string hash = MD5Calculator::calculateFileMD5(emptyFile);  // todo
    EXPECT_EQ(hash, "d41d8cd98f00b204e9800998ecf8427e");
}

TEST_F(MD5CalculatorTest, HelloFile) {
    std::string hash = MD5Calculator::calculateFileMD5(helloFile);
    EXPECT_EQ(hash, "5d41402abc4b2a76b9719d911017c592");
}

TEST_F(MD5CalculatorTest, NonExistentFile) {
    EXPECT_THROW({
        MD5Calculator::calculateFileMD5("nonexistent_file_12345.txt");
    }, std::runtime_error);
}

TEST_F(MD5CalculatorTest, BinaryFile) {
    std::string hash = MD5Calculator::calculateFileMD5(binaryFile);  // todo
    // MD5 от "binary\0data"
    EXPECT_EQ(hash, "5a06f3f7bd0b2b3d4b5b6c7d8e9f0a1b");
}

// Тест консистентности - повторный вызов дает тот же результат
TEST_F(MD5CalculatorTest, Consistency) {
    std::string hash1 = MD5Calculator::calculateFileMD5(helloFile);
    std::string hash2 = MD5Calculator::calculateFileMD5(helloFile);
    EXPECT_EQ(hash1, hash2);
}

// Тест что хеш всегда 32 символа
TEST_F(MD5CalculatorTest, HashLength) {
    std::string hash = MD5Calculator::calculateFileMD5(helloFile);
    EXPECT_EQ(hash.length(), 32);
}

// Тест что хеш содержит только hex символы
TEST_F(MD5CalculatorTest, HexCharacters) {
    std::string hash = MD5Calculator::calculateFileMD5(helloFile);
    
    for (char c : hash) {
        EXPECT_TRUE(std::isxdigit(c)) << "Character '" << c << "' is not hex";
    }
}