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

## Privileges requis

La capture reseau brute necessite des privileges eleves, quel que soit l'OS :

- **Linux** : `my_sniffer` ouvre un socket `AF_PACKET`/`SOCK_RAW`, reserve a
  root ou a un processus disposant de la capability `CAP_NET_RAW`. Deux
  options :
  - lancer avec `sudo` (le plus simple, a refaire a chaque execution) ;
  - donner la capability une fois pour toutes au binaire compile, pour le
    lancer ensuite sans `sudo` :
    ```bash
    sudo setcap cap_net_raw+ep ./build/my_sniffer
    ./build/my_sniffer eth0
    ```
    A refaire apres chaque recompilation (`setcap` s'applique au fichier
    binaire, pas au projet).
- **Windows** : le driver **Npcap** doit etre installe sur la machine (pas
  seulement le SDK utilise pour compiler), et `my_sniffer.exe` doit etre
  lance depuis un terminal **Administrateur**.

Sans ces privileges, le programme s'arrete immediatement avec un message
d'erreur explicite (pas de crash) :
```
my_sniffer: CaptureLinux: failed to open raw socket on 'eth0' (requires root/CAP_NET_RAW): Operation not permitted
```

## Lancer

`my_sniffer` prend le nom de l'interface reseau a ecouter en argument.
Utilise `ip a` (Linux) ou `ipconfig` (Windows) pour lister tes interfaces.

```bash
# Linux
sudo ./build/my_sniffer eth0

# Windows PowerShell avec Visual Studio, terminal Administrateur
./build/Release/my_sniffer.exe eth0
```

Chaque paquet capture est affiche en direct : taille, IP source/destination,
protocole, ports (si TCP/UDP). Arret avec `Ctrl+C`.

## Installer

```bash
cmake --install build --prefix /chemin/d/installation
```

Installe l'executable dans `<prefix>/bin/my_sniffer`. Sans `--prefix`, CMake
utilise l'emplacement standard du systeme (`/usr/local` sur Linux, "Program
Files" sur Windows) — necessite alors les droits d'ecriture correspondants
(souvent `sudo cmake --install build` sur Linux).

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