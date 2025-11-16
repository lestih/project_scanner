#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <memory>

#ifdef SCANNER_CORE_EXPORTS
#define SCANNER_API __declspec(dllexport)
#else
#define SCANNER_API __declspec(dllimport)
#endif

struct ScanResult {
    int totalFiles = 0;
    int malwareFiles = 0;
    int errors = 0;
    double duration = 0.0;
};

class SCANNER_API IScannerCore {
public:
    virtual ~IScannerCore() = default;
    
    virtual bool loadMalwareBase(const std::string& csvPath) = 0;
    virtual ScanResult scanDirectory(const std::string& rootPath, const std::string& logPath) = 0;
};

extern "C" SCANNER_API IScannerCore* createScanner();
extern "C" SCANNER_API void destroyScanner(IScannerCore* scanner);