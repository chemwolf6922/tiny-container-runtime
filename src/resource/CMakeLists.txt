# Embed seccomp.json into the binary as a linkable object.
#
# Usage from other CMakeLists.txt:
#   add_subdirectory(${PATH_TO}/resource)
#   target_link_libraries(your_target PRIVATE seccomp_resource)
#
# This creates a static library "seccomp_resource" that provides:
#   _binary_seccomp_json_start
#   _binary_seccomp_json_end
# Declared in seccomp_json.h

set(SECCOMP_JSON_SRC ${CMAKE_CURRENT_SOURCE_DIR}/seccomp.json)
set(EMBED_BASENAME seccomp)
set(EMBED_BIN ${CMAKE_CURRENT_BINARY_DIR}/${EMBED_BASENAME}.json)
set(EMBED_OBJ ${CMAKE_CURRENT_BINARY_DIR}/${EMBED_BASENAME}.o)

# Copy to build dir with a predictable name so _binary_* symbols are stable
add_custom_command(
  OUTPUT  ${EMBED_BIN}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${SECCOMP_JSON_SRC} ${EMBED_BIN}
  DEPENDS ${SECCOMP_JSON_SRC}
  VERBATIM
)

# Use ld to wrap the raw binary into a relocatable object
add_custom_command(
  OUTPUT  ${EMBED_OBJ}
  COMMAND ${CMAKE_LINKER} -r -b binary -o ${EMBED_OBJ} ${EMBED_BASENAME}.json
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${EMBED_BIN}
  VERBATIM
)

# Mark the .o as generated so CMake doesn't look for it at configure time
set_source_files_properties(${EMBED_OBJ} PROPERTIES GENERATED TRUE EXTERNAL_OBJECT TRUE)

# Build a static library that bundles the embedded object
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/seccomp_resource_stub.c "/* stub */\n")
add_library(seccomp_resource STATIC
  ${CMAKE_CURRENT_BINARY_DIR}/seccomp_resource_stub.c
  ${EMBED_OBJ}
)
target_include_directories(seccomp_resource PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
