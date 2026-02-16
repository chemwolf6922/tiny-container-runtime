# Embedded Seccomp Profile (`src/resource/`)

The default seccomp profile (`seccomp.json`) is embedded directly into the binary at link time so the runtime has a built-in policy without needing an external file on the target device.

## Files

| File | Purpose |
|---|---|
| `seccomp.json` | Default seccomp profile (compacted with `jq -c`) |
| `seccomp_json.h` | C header declaring the embedded data symbols and convenience macros |
| `CMakeLists.txt` | CMake module that builds a `seccomp_resource` static library containing the embedded JSON |

## How It Works

1. **Copy** — `seccomp.json` is copied to the build directory with a predictable basename (`seccomp.json`).
2. **Embed** — `ld -r -b binary` wraps the raw file into a relocatable object (`seccomp.o`), producing linker symbols derived from the filename:
   - `_binary_seccomp_json_start` — first byte
   - `_binary_seccomp_json_end` — one past the last byte
3. **Package** — The object is bundled into a static library (`libseccomp_resource.a`) so CMake can link it like any other library.

## Usage

### CMake

```cmake
add_subdirectory(path/to/src/resource ${CMAKE_CURRENT_BINARY_DIR}/resource)
target_link_libraries(your_target PRIVATE seccomp_resource)
```

The `target_include_directories` for the header is propagated automatically.

### C Code

```c
#include "seccomp_json.h"
#include <cjson/cJSON.h>

cJSON *profile = cJSON_ParseWithLength(SECCOMP_JSON_DATA, SECCOMP_JSON_LEN);
// ... use profile ...
cJSON_Delete(profile);
```

| Macro | Type | Description |
|---|---|---|
| `SECCOMP_JSON_DATA` | `const char *` | Pointer to the first byte of the embedded JSON |
| `SECCOMP_JSON_LEN` | `size_t` | Byte length of the embedded JSON |

> **Note:** The embedded data is **not** null-terminated. Use `cJSON_ParseWithLength` or copy to a null-terminated buffer before parsing.

## Updating the Profile

Edit `src/resource/seccomp.json` and rebuild. The CMake custom commands will re-embed automatically. To re-compact after formatting changes:

```sh
jq -c . src/resource/seccomp.json > tmp.json && mv tmp.json src/resource/seccomp.json
```
