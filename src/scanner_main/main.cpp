#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <filesystem>
#include <fstream>
#include "scanner_core.h"


namespace fs = std::filesystem;

class ScannerApp {
private:
    HMODULE dllHandle;
    IScannerCore* scanner;
    
    typedef IScannerCore* (*CreateScannerFunc)();
    typedef void (*DestroyScannerFunc)(IScannerCore*);

    CreateScannerFunc createScanner;
    DestroyScannerFunc destroyScanner;

public:
    ScannerApp() : dllHandle(nullptr), scanner(nullptr) {}
    
    ~ScannerApp() {
        cleanup();
    }

    bool initialize() {
        dllHandle = LoadLibraryA("scanner_core.dll");
        if (!dllHandle) {
            std::cerr << "Failed to load scanner_core.dll" << std::endl;
            return false;
        }

        createScanner = (CreateScannerFunc)GetProcAddress(dllHandle, "createScanner");
        destroyScanner = (DestroyScannerFunc)GetProcAddress(dllHandle, "destroyScanner");

        if (!createScanner || !destroyScanner) {
            std::cerr << "Failed to get function pointers from DLL" << std::endl;
            return false;
        }

        scanner = createScanner();
        return scanner != nullptr;
    }

    void cleanup() {
        if (scanner) {
            destroyScanner(scanner);
            scanner = nullptr;
        }
        if (dllHandle) {
            FreeLibrary(dllHandle);
            dllHandle = nullptr;
        }
    }

    void printUsage() {
        std::cout << "Usage: scanner.exe --base base.csv --log report.log --path c:\\folder" << std::endl;
    }

    int run(int argc, char* argv[]) {
        std::string basePath, logPath, scanPath;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--base" && i + 1 < argc) {
                basePath = argv[++i];
            } else if (arg == "--log" && i + 1 < argc) {
                logPath = argv[++i];
            } else if (arg == "--path" && i + 1 < argc) {
                scanPath = argv[++i];
            }
        }
        std::cout << "Arguments" << std::endl;
        std::cout << basePath << std::endl;
        std::cout << logPath << std::endl;
        std::cout << scanPath << std::endl;
        if (basePath.empty() || logPath.empty() || scanPath.empty()) {
            printUsage();
            return 1;
        }

        if (!initialize()) {
            return 1;
        }

        // Загрузка базы вредоносных хешей
        if (!scanner->loadMalwareBase(basePath)) {
            std::cerr << "Failed to load malware base from: " << basePath << std::endl;
            return 1;
        }

        std::cout << "Starting scan of directory: " << scanPath << std::endl;
        std::cout << "Log file: " << logPath << std::endl;

        ScanResult result = scanner->scanDirectory(scanPath, logPath);

        std::cout << "\n=== Scan Report ===" << std::endl;
        std::cout << "Total files processed: " << result.totalFiles << std::endl;
        std::cout << "Malware files found: " << result.malwareFiles << std::endl;
        std::cout << "Errors: " << result.errors << std::endl;
        std::cout << "Time elapsed: " << result.duration << " seconds" << std::endl;

        return 0;
    }
};

int main(int argc, char* argv[]) {
    ScannerApp app;
    return app.run(argc, argv);
}