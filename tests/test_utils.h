#pragma once

#include <filesystem>
#include <fstream>
#include <string>

namespace test_utils {
    
    /**
     * Создает временный файл с заданным содержимым
     */
    inline std::string createTempFile(const std::string& content, const std::string& extension = ".txt") {
        std::filesystem::path tempDir = std::filesystem::temp_directory_path();
        std::filesystem::path tempFile = tempDir / ("test_" + std::to_string(std::time(nullptr)) + extension);
        
        std::ofstream file(tempFile);
        file << content;
        file.close();
        
        return tempFile.string();
    }
    
    /**
     * Создает временную директорию
     */
    inline std::string createTempDir() {
        std::filesystem::path tempDir = std::filesystem::temp_directory_path();
        std::filesystem::path testDir = tempDir / ("test_dir_" + std::to_string(std::time(nullptr)));
        
        std::filesystem::create_directories(testDir);
        return testDir.string();
    }
    
    /**
     * Удаляет файл или директорию
     */
    inline void cleanup(const std::string& path) {
        try {
            if (std::filesystem::exists(path)) {
                std::filesystem::remove_all(path);
            }
        } catch (...) {
            // Игнорируем ошибки при очистке
        }
    }
}