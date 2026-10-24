# ==== CMakeLists.txt: capp — C референс-сервер (kernel/examples) ====
#
# Собирает single-ELF прикладной сервер из capp.c под
# x86_64-unknown-none с адресом загрузки 0x40000000
# (init.ld — пользовательский линкер-скрипт из kernel/crates/user/init).
# Линк с libuserlib.a (_start + l4_* обёртки сисколов).
#
# Выход: kernel/examples/build/<config>/capp — загружаемый через boot-цепочку
# (см. kernel/scripts/boot_cfg_c.xml).

add_executable(capp capp.c)

target_include_directories(capp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${USERLIB_INCLUDE}
)

target_compile_options(capp PRIVATE
    ${FREESTANDING_C_OPTIONS}
)

target_link_options(capp PRIVATE
    ${FREESTANDING_LINK_OPTIONS}
)

target_link_libraries(capp PRIVATE
    ${USERLIB_STATIC}
)

set_target_properties(capp PROPERTIES
    OUTPUT_NAME capp
)