# Avanguard
## The Win32 Anti-Intrusion Library
Avanguard is the Windows anti-injection library written on C++.
### 🔙🔚 Current and in-dev capabilities:
* [✔️] Threads filter (against of CreateRemoteThread)
* [✔️] Modules filter
* [✔️] Memory filter (support of JIT-based languages)
* [✔️] Stacktrace checker
* [✔️] Windows hooks detection
* [❌] AppInit_DLLs detection
* [❌] Memory mapping based injects detection
* [❌] APC filter
* [❌] Threads context filter (to prevent a context steel)
* [❌] HWIDs collector
* [❌] Java/C#/Delphi bindings and API
* [❌] Anti-macroses (virtual input blocking)
* [❌] Anti-debugging techniques
* [❌] Self-modification support
* [❌] DACLs-based protection

### 📝 Dependencies:
* [HookLib](https://github.com/HoShiMin/HookLib) - lightweight and convenient hook library written on pure C and NativeAPI
* [Zydis](https://github.com/zyantific/zydis) - extremely lightweight disassembler
* [t1ha](https://github.com/leo-yuriev/t1ha) - the fastest hash ever
* [xorstr](https://github.com/JustasMasiulis/xorstr) - a heavily vectorized C++17 compile-time strings encryptor

### 📐 How to use:
First of all, clone it with all dependencies:
```
git clone --recursive https://github.com/HoShiMin/Avanguard.git
```

All you need is to build the Avanguard.dll and add it to your application's import table.
```cpp
#include <cstdio>
#include <Windows.h>

#include <AvnApi.h>
#pragma comment(lib, "Avanguard.lib")

int main()
{
    // Using of Avanguard's symbols binds it to your app:
    printf("[i] AvnStub: %p\n", Stub);
    while (true);
}
```

Or you can add it to import table manually using PE editors like [CFF Explorer](https://ntcore.com/?page_id=388):
1. Right click on your exe/dll
2. Open with CFF Explorer
3. `Import Adder` tree entry -> Add -> Choose Avanguard.dll
4. Choose `Stub` -> Import by name -> Rebuild import table
5. Go to `Import directory` tree entry
6. Right click on Avanguard.dll -> Move up
7. Move it on the top of import list (it allows Avanguard.dll to load before of all another dlls)
8. Press `save` button (💾 button at the top)
9. Done! Now put the Avanguard.dll to the same folder as your exe/dll.

### 🛠 Settings:
You can change enabled features in the `AvnDefinitions.h` file.  
If you want to use it with JIT, you MUST enable `FEATURE_MEMORY_FILTER` to prevent a false detections.
