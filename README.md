# c2.py

## Requirements

* Python3
* ninja
* CMake
* Visual Studio 2022 (if using Windows)

- [c2.py](#c2py)
  - [Requirements](#requirements)
  - [Introduction](#introduction)
  - [Usage](#usage)
  - [Windows Support](#windows-support)

## Introduction

c2.py is a tool similar to Boost's b2 build tool in the sense that it specializes in building and running tests for a
given library under several different configurations.

The crux of the problem being solved is that Boost libraries have to work under several different compilers and versions.
It's not uncommon for a single Boost library to be built with more than a dozen configurations, even on a single host. For example, consider the following b2 command:

```bash
./b2 libs/hash2/test cxxstd=11,14,17,20,23 toolset=gcc-13,gcc-14,gcc-15 variant=debug,release
```

The above command will build the Hash2 library's tests using the Cartesian product of configuration option above. This results in a 5 * 3 * 2 builds, which is 30 total variations!

c2.py is a tool that does something similar to this, except it works natively with CMake projects instead of Jamfiles.

As an example, the above command would be written with c2.py using:

```bash
./c2.py test \
    --source-dir /path/to/boost-root   \ # path to the project's source directory
    --target tests                     \ # cmake target to build
    --cmake-toolchain-file boost.cmake \ # a toolchain file we use for setting cache entries
    --cxxstd 11,14,17,20,23            \ # the C++ standards we want to build
    --toolset gcc-13,gcc-14,gcc-15     \ # the compiler suite we wish to use
    --variant debug,release            \ # determine if we should build Debug or Release
    -j20
```

`boost.cmake` would roughly look like this:
```bash
exbigboss@pleiades ~/c/c2py (master)> cat boost.cmake
set(BOOST_INCLUDE_LIBRARIES "hash2" CACHE STRING "")
```

More control over build variants in the produced matrix can be hand-specified using a file, such as:
```
./c2.py build \
    --source-dir /path/to/boost-root \
    --target tests \
    --toolchains toolchain-hash2.json \
    -j20
```

`toolchain-hash2.json` can, for example, contain:
```json
[
    {
        "cxxstd": "20",
        "toolset": "clang-20",
        "address_model": "64",
        "link": "shared",
        "toolchain_file": "boost.cmake",
        "project_name": "boost_hash2"
    },
    {
        "cxxstd": "20",
        "toolset": "gcc-15",
        "address_model": "64",
        "link": "shared",
        "toolchain_file": "boost.cmake",
        "project_name": "boost_hash2"
    }
]
```

This will cause c2.py to generate only two builds. `project_name` is used to specify a prefix to use when creating a mangled build directory name.

## Usage

```
usage: c2.py [-h] [--source-dir SOURCE_DIR] [--cmake-path CMAKE_PATH] [--ninja-path NINJA_PATH] [-j JOBS] [--target TARGET] [--cxxstd CXXSTD] [--toolset TOOLSET] [--variant VARIANT]
             [--address-model ADDRESS_MODEL] [--link LINK] [--ubsan] [--asan] [--skip-configure] [--cxxflags CXXFLAGS] [--ctestflags CTESTFLAGS] [--winsdk-version WINSDK_VERSION]
             [--cmake-toolchain-file CMAKE_TOOLCHAIN_FILE] [--toolchains TOOLCHAINS]
             command

Parse all build options and assemble the matrix.

positional arguments:
  command               Main driver command. Either just `build` or `test`. `test` implies `build` but also invokes `ctest` for each generated build directory.

options:
  -h, --help            show this help message and exit
  --source-dir SOURCE_DIR
                        Name of the library to build tests for.
  --cmake-path CMAKE_PATH
                        Path to a working CMake executable.
  --ninja-path NINJA_PATH
                        Path to a working Ninja executable.
  -j JOBS               Number of jobs used to build with CMake.
  --target TARGET       Name of the CMake target to be used in the `cmake --build <build_dir> --target <target>` call.
  --cxxstd CXXSTD       A comma-separated list of C++ standard versions (e.g., 'cxxstd=11,17,20').
  --toolset TOOLSET     A comma-separated list of C++ toolchains to use (e.g. toolset=gcc-14,clang-19 [no '++' required])
  --variant VARIANT     A comma-separated list of C++ build types (e.g variant=debug,release or variant=release)
  --address-model ADDRESS_MODEL
                        A comma-separated list of architectures (e.g. address-model=32,64)
  --link LINK           A comma-separated list of link models (e.g. link=static,shared)
  --ubsan               Build with -fsanitize=undefined
  --asan                Build with -fsanitize=address
  --skip-configure      Skip the CMake configuration step
  --cxxflags CXXFLAGS   Add custom compiler options that will be added to `CMAKE_CXX_FLAGS_INIT` during configure time
  --ctestflags CTESTFLAGS
                        Additional arguments to be passed to ctest during test running
  --winsdk-version WINSDK_VERSION
                        Version of the Windows SDK to use (e.g. 10.0.22621.0). Commonly found in: "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0"
  --cmake-toolchain-file CMAKE_TOOLCHAIN_FILE
                        Path to the CMake toolchain file that will be common to all builds generated.
  --toolchains TOOLCHAINS
                        Path to a JSON file containing an array of build variants. This option will override all over the build matrix generation options specified.
```

## Windows Support

To specify a toolchain on Windows, the format is just `msvc-14.<N>` where `N` is one of the subversions that will be passed to vcvarsall.bat
when the script probes for toolchains.

So for example, one can pass `--toolset msvc-14.0,msvc-14.1,msvc-14.4,clang,clang-win`. `clang-win` will invoke the `clang-cl` driver as its compiler.
`14.0`, `14.1`, `14.4` will be passed verbatim to the vcvarsall.bat script.

A version of the Windows SDK can also be supplied by using `--windsdk-version` with a value that's valid for vcvarsall.bat.

Because cl.exe has a fundamental reliance on the environment, c2.py works around this by probing the host using a helper Batch script, `get_vcvars.bat`.
This script invokes vcvarsall.bat and stores the results in a set of files that c2.py then reads and uses to assemble the compile commands.
