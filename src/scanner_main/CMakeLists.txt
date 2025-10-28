add_executable(scanner_main
    main.cpp
)

# Линкуем с нашей DLL
target_link_libraries(scanner_main PRIVATE scanner_core)

# Копируем DLL рядом с исполняемым файлом
add_custom_command(TARGET scanner_main POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:scanner_core>
    $<TARGET_FILE_DIR:scanner_main>
)