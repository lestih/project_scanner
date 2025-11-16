# Antivirus Scanner

Утилита для сканирования файлов в директориях на наличие вредоносного содержимого путем проверки MD5-хешей.

---

## Структура проекта

```
.
├── CMakeLists.txt                          # Корневой скрипт сборки проекта
├── README.md                               # Документация проекта
├── base.csv                                # Пример базы вредоносных хешей
├── report.log                              # Пример файла отчета
│
├── src/                                    # Исходный код проекта
│   ├── scanner_core/                       # Основная логика (DLL)
│   │   ├── CMakeLists.txt                  # Сборка DLL библиотеки
│   │   ├── scanner_core.h                  # Интерфейс IScannerCore
│   │   ├── scanner_core.cpp               # Реализация сканера
│   │   └── md5_calculator.h               # Калькулятор MD5 хешей
│   │
│   └── scanner_main/                       # Консольное приложение
│       ├── CMakeLists.txt                  # Сборка исполняемого файла
│       └── main.cpp                        # Точка входа, CLI интерфейс
│
└── tests/                                  # Модульные тесты
    ├── CMakeLists.txt                      # Конфигурация тестов
    ├── test_md5_calculator.cpp            # Тесты MD5 калькулятора
    ├── test_scanner_core.cpp              # Тесты ядра сканера
    └── test_utils.h                       # Вспомогательные утилиты для тестов
```

---

## Основные модули и их назначение

### scanner_core (DLL библиотека)
- `scanner_core.h` — Интерфейс IScannerCore с методами для загрузки базы хешей и сканирования.
- `scanner_core.cpp` — Основная логика сканирования с многопоточной обработкой
- `md5_calculator.h` —  Класс для вычисления MD5 хешей файлов с использованием Windows CryptoAPI

### scanner_main (Консольное приложение)
- `main.cpp` —  Интерфейс командной строки, загрузка DLL, вывод результатов

### tests (Модульные тесты)
- `test_md5_calculator.cpp` — Тестирование корректности вычисления MD5 хешей
- `test_scanner_core.cpp` — Тестирование функциональности сканера
- `test_utils.h` — Утилиты для создания временных файлов в тестах

### Сборка
```
# Создание директории для сборки
mkdir build
cd build

# Генерация проектов CMake
cmake ..

# Сборка проекта
cmake --build . --config Release

# Или для сборки с тестами
cmake --build . --config Release --target ALL_BUILD
```

### Использование
- `--base` — Путь к CSV файлу с базой вредоносных хешей 
- `--log` —  Путь к файлу для записи лога обнаруженных угроз
- `--path` — Путь к директории для сканирования
```
scanner_main.exe --base base.csv --log report.log --path C:\scan_folder
```

### Формат базы вредоносных хешей

# CSV файл с разделителем ;:
```
a9963513d093ffb2bc7ceb9807771ad4;Exploit
ac6204ffeb36d2320e52f1d551cfa370;Dropper
8ee70903f43b227eeb971262268af5a8;Downloader
```

### Пример вывода

```
Starting scan of directory: C:\scan_folder
Log file: report.log

=== Scan Report ===
Total files processed: 1542
Malware files found: 3
Errors: 2
Time elapsed: 12.45 seconds
```