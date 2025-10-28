#pragma once

#include <string>
#include <windows.h>
#include <wincrypt.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>

/**
 * Класс для вычисления MD5 хеша файлов с использованием Windows CryptoAPI
 */
class MD5Calculator {
public:
    static std::string calculateFileMD5(const std::string& filePath) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        HANDLE hFile = INVALID_HANDLE_VALUE;
        
        // Константы
        const DWORD BUFFER_SIZE = 8192;
        const DWORD MD5_LENGTH = 16;
        
        try {
            // Открываем файл
            hFile = CreateFileA(filePath.c_str(), 
                               GENERIC_READ, 
                               FILE_SHARE_READ, 
                               NULL, 
                               OPEN_EXISTING, 
                               FILE_FLAG_SEQUENTIAL_SCAN, 
                               NULL);
            
            if (hFile == INVALID_HANDLE_VALUE) {
                throw std::runtime_error("Cannot open file: " + filePath);
            }
            
            // Получаем хэндл криптопровайдера
            if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                throw std::runtime_error("CryptAcquireContext failed");
            }
            
            if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
                throw std::runtime_error("CryptCreateHash failed");
            }
            
            BYTE buffer[BUFFER_SIZE];
            DWORD bytesRead = 0;
            
            while (ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL) && bytesRead > 0) {
                if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
                    throw std::runtime_error("CryptHashData failed");
                }
            }

            DWORD lastError = GetLastError();
            if (lastError != ERROR_SUCCESS && lastError != ERROR_HANDLE_EOF) {
                throw std::runtime_error("File read error: " + std::to_string(lastError));
            }
            
            BYTE hash[MD5_LENGTH];
            DWORD hashLength = MD5_LENGTH;
            
            if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLength, 0)) {
                throw std::runtime_error("CryptGetHashParam failed");
            }

            if (hashLength != MD5_LENGTH) {
                throw std::runtime_error("Invalid hash length");
            }
            
            std::string result = bytesToHexString(hash, hashLength);
            
            cleanup(hHash, hProv, hFile);
            
            return result;
            
        } catch (...) {
            cleanup(hHash, hProv, hFile);
            throw;
        }
    }

private:
    static std::string bytesToHexString(const BYTE* data, DWORD len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < len; ++i) {
            ss << std::setw(2) << static_cast<unsigned int>(data[i]);
        }
        return ss.str();
    }
    
    static void cleanup(HCRYPTHASH hHash, HCRYPTPROV hProv, HANDLE hFile) {
        if (hHash) {
            CryptDestroyHash(hHash);
        }
        if (hProv) {
            CryptReleaseContext(hProv, 0);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
    }
};