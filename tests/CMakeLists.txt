include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
)

FetchContent_MakeAvailable(googletest)

# Тесты для MD5Calculator
add_executable(test_md5_calculator
    test_md5_calculator.cpp
)

target_link_libraries(test_md5_calculator
    PRIVATE
        scanner_core
        GTest::gtest_main
)

# Тесты для ScannerCore
add_executable(test_scanner_core
    test_scanner_core.cpp
)

target_link_libraries(test_scanner_core
    PRIVATE
        scanner_core
        GTest::gtest_main
)

# Копируем DLL для тестов
add_custom_command(TARGET test_md5_calculator POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:scanner_core>
    $<TARGET_FILE_DIR:test_md5_calculator>
)

add_custom_command(TARGET test_scanner_core POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:scanner_core>
    $<TARGET_FILE_DIR:test_scanner_core>
)

include(GoogleTest)
gtest_discover_tests(test_md5_calculator)
gtest_discover_tests(test_scanner_core)