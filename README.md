# My_sniffer

Base de projet C++ construite avec CMake et Conan.

## Prerequis

- CMake 3.16 ou plus recent
- Conan 2
- Un compilateur C++17
- GoogleTest 1.14.0 (installe automatiquement par Conan)

Sur Windows, installe aussi Npcap avec son **Npcap SDK**. Le SDK est
necessaire pour compiler, et le runtime Npcap doit etre installe sur la machine
qui execute le programme.

## Compiler

```bash
conan profile detect --force
conan install . --output-folder=build --build=missing
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE="$PWD/build/conan_toolchain.cmake"
cmake --build build
```

Le projet detecte automatiquement le systeme cible. Sur Windows, Conan
selectionne le profil Windows et CMake utilise Visual Studio ou MinGW selon
le compilateur detecte. Sur Linux, CMake utilise GCC ou Clang.

### Windows PowerShell

```powershell
conan profile detect --force
conan install . --output-folder=build --build=missing
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE="$PWD/build/conan_toolchain.cmake"
cmake --build build --config Release
```

Si le SDK Npcap n'est pas dans un emplacement standard, indique sa racine :

```powershell
$env:NPCAP_SDK_DIR = "C:\Npcap-SDK"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release `
	-DCMAKE_TOOLCHAIN_FILE="$PWD/build/conan_toolchain.cmake" `
	-DNPCAP_SDK_DIR="$env:NPCAP_SDK_DIR"
cmake --build build --config Release
```

Avec Visual Studio, l'executable sera generalement dans
`build/Release/my_sniffer.exe`.

L'executable se trouve ensuite dans `build/my_sniffer`.

## Lancer

```bash
# Linux
./build/my_sniffer

# Windows PowerShell avec Visual Studio
./build/Release/my_sniffer.exe
```

## Tester

```bash
ctest --test-dir build --output-on-failure
```

Les tests GoogleTest sont dans `tests/`. Pour executer directement le binaire
de test :

```bash
./build/my_sniffer_tests
```

Pour compiler sans Conan, la commande classique reste disponible :

```bash
cmake -S . -B build
cmake --build build
```

Le code applicatif se trouve dans `src/`, les headers publics dans `include/` et les tests dans `tests/`.