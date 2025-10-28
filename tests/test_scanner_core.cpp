#include <gtest/gtest.h>
#include "scanner_core.h"
#include "test_utils.h"
#include <filesystem>
#include <fstream>

class ScannerCoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        scanner = createScanner();
        
        testDir = test_utils::createTempDir();
        
        // Создаем тестовую базу вредоносных хешей
        malwareBase = test_utils::createTempFile(
            "d41d8cd98f00b204e9800998ecf8427e;TestMalware1\n"
            "5d41402abc4b2a76b9719d911017c592;TestMalware2\n"
            "9f86d081884c7d659a2feaa0c55ad015;TestMalware3\n",
            ".csv"
        );
    }
    
    void TearDown() override {
        destroyScanner(scanner);
        test_utils::cleanup(testDir);
        test_utils::cleanup(malwareBase);
    }
    
    IScannerCore* scanner;
    std::string testDir;
    std::string malwareBase;
};

// Тест загрузки базы вредоносных хешей
TEST_F(ScannerCoreTest, LoadMalwareBase_Success) {
    bool result = scanner->loadMalwareBase(malwareBase);
    EXPECT_TRUE(result);
}

// Тест загрузки несуществующей базы
TEST_F(ScannerCoreTest, LoadMalwareBase_FileNotFound) {
    bool result = scanner->loadMalwareBase("nonexistent_base.csv");
    EXPECT_FALSE(result);
}

// Тест сканирования пустой директории
TEST_F(ScannerCoreTest, ScanDirectory_Empty) {
    scanner->loadMalwareBase(malwareBase);
    
    std::string logFile = test_utils::createTempFile("", ".log");
    ScanResult result = scanner->scanDirectory(testDir, logFile);
    
    EXPECT_EQ(result.totalFiles, 0);
    EXPECT_EQ(result.malwareFiles, 0);
    EXPECT_EQ(result.errors, 0);
    EXPECT_GE(result.duration, 0.0);
    
    test_utils::cleanup(logFile);
}

// Тест сканирования директории с безопасными файлами
TEST_F(ScannerCoreTest, ScanDirectory_SafeFiles) {
    scanner->loadMalwareBase(malwareBase);
    
    // Создаем безопасные файлы
    std::string safeFile1 = testDir + "/safe1.txt";
    std::ofstream(safeFile1) << "safe content 1";
    
    std::string safeFile2 = testDir + "/safe2.dat";
    std::ofstream(safeFile2) << "safe content 2";
    
    std::string logFile = test_utils::createTempFile("", ".log");
    ScanResult result = scanner->scanDirectory(testDir, logFile);
    
    EXPECT_EQ(result.totalFiles, 2);
    EXPECT_EQ(result.malwareFiles, 0);
    EXPECT_GE(result.duration, 0.0);
    
    test_utils::cleanup(logFile);
}

// Тест сканирования директории с вредоносными файлами
TEST_F(ScannerCoreTest, ScanDirectory_MalwareFiles) {
    scanner->loadMalwareBase(malwareBase);
    
    // Создаем вредоносные файлы
    std::string malware1 = testDir + "/malware1.exe";
    std::ofstream(malware1) << "";  // Пустой файл -> d41d8cd98f00b204e9800998ecf8427e
    
    std::string malware2 = testDir + "/malware2.dll";
    std::ofstream(malware2) << "hello";  // "hello" -> 5d41402abc4b2a76b9719d911017c592
    
    std::string logFile = test_utils::createTempFile("", ".log");
    ScanResult result = scanner->scanDirectory(testDir, logFile);
    
    EXPECT_EQ(result.totalFiles, 2);
    EXPECT_EQ(result.malwareFiles, 2);
    EXPECT_GE(result.duration, 0.0);
    
    // Проверяем что лог создан и содержит информацию
    std::ifstream log(logFile);
    std::string logContent((std::istreambuf_iterator<char>(log)), 
                          std::istreambuf_iterator<char>());
    
    EXPECT_FALSE(logContent.empty());
    EXPECT_NE(logContent.find("malware1.exe"), std::string::npos);
    EXPECT_NE(logContent.find("malware2.dll"), std::string::npos);
    
    test_utils::cleanup(logFile);
}

// Тест сканирования несуществующей директории
TEST_F(ScannerCoreTest, ScanDirectory_NonExistent) {
    scanner->loadMalwareBase(malwareBase);
    
    std::string logFile = test_utils::createTempFile("", ".log");
    ScanResult result = scanner->scanDirectory("/nonexistent/directory/123", logFile);
    
    EXPECT_GT(result.errors, 0);
    
    test_utils::cleanup(logFile);
}

// Тест структуры ScanResult
TEST_F(ScannerCoreTest, ScanResult_Structure) {
    ScanResult result;
    
    result.totalFiles = 10;
    result.malwareFiles = 2;
    result.errors = 1;
    result.duration = 1.5;
    
    EXPECT_EQ(result.totalFiles, 10);
    EXPECT_EQ(result.malwareFiles, 2);
    EXPECT_EQ(result.errors, 1);
    EXPECT_EQ(result.duration, 1.5);
}