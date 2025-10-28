# Создаем DLL библиотеку
add_library(scanner_core SHARED
    scanner_core.cpp
)

# Добавляем определения для экспорта символов
target_compile_definitions(scanner_core 
    PRIVATE SCANNER_CORE_EXPORTS
    PUBLIC USING_SCANNER_CORE_DLL
)

# Линкуем с Windows CryptoAPI библиотеками
target_link_libraries(scanner_core PRIVATE advapi32)

if(WIN32)
    set_target_properties(scanner_core PROPERTIES
        SUFFIX ".dll"
        OUTPUT_NAME "scanner_core"
    )
endif()

target_include_directories(scanner_core 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}
)