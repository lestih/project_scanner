#include "scanner_core.h"
#include <filesystem>
#include <fstream>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iostream>
#include <functional>
#include <stdexcept>
#include <iomanip>
#include "md5_calculator.h"
// #include <openssl/md5.h>
// #include <openssl/evp.h>  // todo

namespace fs = std::filesystem;

class ThreadPool {
public:
    ThreadPool(size_t threadCount) 
        : ThreadPoolSize_(threadCount),
          wait_(true),
          finish_(false) {
        for (size_t i = 0; i < threadCount; ++i) {
            threads_.emplace_back([this]() { this->ThreadFunction(); });
        }
    }
    
    void PushTask(const std::function<void()>& task) {
        if (finish_) {
            throw std::runtime_error("ThreadPool is finished");
        }
        {
            std::unique_lock<std::mutex> lock(mutex_);
            tasks_.push(task);
        }
        taskPushed_.notify_one();
    }

    void Terminate(bool wait) {
        std::unique_lock<std::mutex> lock(mutex_);

        finish_ = true;
        wait_ = wait;
        
        if (wait_){
            TerminateWait_.wait(lock, [this]() { return tasks_.empty(); });
        }
        
        taskPushed_.notify_all();
        lock.unlock();

        for (auto& thread: threads_){
            thread.join();
        }
    }

    bool IsActive() const {
        std::unique_lock<std::mutex> lock(mutex_);
        return !finish_;
    }

    size_t QueueSize() const {
        std::unique_lock<std::mutex> lock_(mutex_);
        return tasks_.size();
    }
    
private:
    mutable std::mutex mutex_;
    std::condition_variable taskPushed_;
    std::condition_variable TerminateWait_;
    size_t ThreadPoolSize_;
    bool wait_;
    bool finish_;

    std::queue<std::function<void()>> tasks_;
    std::vector<std::thread> threads_;
    
    void ThreadFunction() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                taskPushed_.wait(lock, [this]() { return finish_ || !tasks_.empty(); });

                if (finish_ && (tasks_.empty() || !wait_)) {
                    if (wait_ && tasks_.empty()) {
                        TerminateWait_.notify_one();
                    }
                    return;
                }

                task = tasks_.front();
                tasks_.pop();
            }
            
            task();
        }
    }
};

class ScannerCore : public IScannerCore {
private:
    std::unordered_map<std::string, std::string> malwareHashes;
    std::mutex logMutex;
    
    struct FileTask {
        std::string path;  // полный путь
        std::string relativePath;  // путь от корня 
    };

public:
    // загружает базу вредоносных хешей в мапу
    bool loadMalwareBase(const std::string& csvPath) override {
        std::ifstream file(csvPath);
        if (!file.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            size_t delimiterPos = line.find(';');
            if (delimiterPos != std::string::npos) {
                std::string hash = line.substr(0, delimiterPos);
                std::string verdict = line.substr(delimiterPos + 1);
                malwareHashes[hash] = verdict;
            }
        }
        return true;
    }

    // main функция сканирования
    ScanResult scanDirectory(const std::string& rootPath, const std::string& logPath) override {
        auto start = std::chrono::high_resolution_clock::now();
        ScanResult result;
        
        std::vector<FileTask> fileTasks;
        try {
            for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
                if (entry.is_regular_file()) {
                    FileTask task;
                    task.path = entry.path().string();
                    task.relativePath = fs::relative(entry.path(), rootPath).string();
                    fileTasks.push_back(task);
                }
            }
        } catch (const fs::filesystem_error& e) {
            result.errors++;
        }

        result.totalFiles = fileTasks.size();

        if (fileTasks.empty()) {
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> duration = end - start;
            result.duration = duration.count();
            return result;
        }

        unsigned int numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 1;
        
        ThreadPool threadPool(numThreads);

        std::ofstream logFile(logPath);
        // if (!logFile.is_open()) {
        //     result.errors++;
        //     auto end = std::chrono::high_resolution_clock::now();  // todo
        //     std::chrono::duration<double> duration = end - start;
        //     result.duration = duration.count();
        //     return result;
        // }

        std::atomic<int> malwareFound{0};
        std::atomic<int> fileErrors{0};

        for (const auto& task : fileTasks) {
            threadPool.PushTask([this, task, &logFile,  &malwareFound, &fileErrors]() {
                processFile(task, logFile,  malwareFound, fileErrors);
            });
        }

        threadPool.Terminate(true);

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = end - start;

        result.malwareFiles = malwareFound;
        result.errors += fileErrors;
        result.duration = duration.count();

        return result;
    }

private:
    void processFile(const FileTask& task, std::ofstream& logFile,  
                    std::atomic<int>& malwareFound,
                    std::atomic<int>& fileErrors) {
        try {
            std::string hash = MD5Calculator::calculateFileMD5(task.path);

            auto it = malwareHashes.find(hash);
            if (it != malwareHashes.end()) {
                malwareFound++;
                
                std::lock_guard<std::mutex> lock(logMutex);
                logFile << task.path << ";" << hash << ";" << it->second << std::endl;
            }
        } catch (const std::exception& e) {
            fileErrors++;
        }
    }
};

extern "C" SCANNER_API IScannerCore* createScanner() {
    return new ScannerCore();
}

extern "C" SCANNER_API void destroyScanner(IScannerCore* scanner) {
    delete scanner;
}