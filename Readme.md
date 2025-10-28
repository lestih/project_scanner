# Antivirus Scanner

Проект представляет собой многопоточный антивирусный сканер для Windows, который проверяет файлы по базе MD5-хешей известных вредоносных программ.

## Архитектура проекта

Проект состоит из нескольких компонентов:

### Основные модули

- **Scanner Core** (`scanner_core`) - ядро сканера с многопоточной обработкой
- **MD5 Calculator** - вычисление хешей файлов с использованием Windows CryptoAPI
- **Console Application** - консольное приложение для работы со сканером
- **Unit Tests** - модульные тесты для проверки функциональности

## Требования

- Windows 7+
- Visual Studio 2019+ (для сборки)
- CMake 3.15+ (опционально)
- Google Test (для тестов)

## Сборка проекта

### Способ 1: Visual Studio
1. Откройте решение `scanner.sln`
2. Выберите конфигурацию (Debug/Release)
3. Соберите решение (Build Solution)

### Способ 2: CMake
```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release