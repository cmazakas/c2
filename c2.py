#!/usr/bin/python3

# pylint: disable=global-statement,line-too-long

"""Python-based version of b2 using pure CMake"""

import os
import shutil
import subprocess
import dataclasses
import argparse
import sys
import pprint
import itertools
import json

num_cores = os.cpu_count()

BUILD_ROOT = os.path.abspath("build_c2py")
SOURCE_ROOT = os.path.abspath("")
TARGET: str = "all"
CMAKE_PATH: str | None = None
NINJA_PATH: str | None = None
COMMAND_MODE: str | None = None
CMAKE_GENERATOR: str | None = None
NUM_JOBS: int | None = None
UBSAN: bool | None = None
ASAN: bool | None = None
NO_CONFIGURE: bool | None = None
CXXFLAGS: str | None = None
CTESTFLAGS: str | None = None
WINSDK_VERSION: str | None = None
CMAKE_TOOLCHAIN_FILE: str | None = None

@dataclasses.dataclass
class BuildVariant:
    """Represents a CMake-based build"""

    address_model: str | None = None
    toolset: str | None = None
    variant: str | None = None
    cxxstd: str | None = None
    link: str | None = None
    toolchain_file: str | None = None
    project_name: str | None = None


def is_windows():
    """Helper used to determine if we're running on Windows or not-Windows"""
    return os.name == "nt"


def build_variant_to_build_dir_fragment(build_variant: BuildVariant):
    """A detail function intended to build the tree fragment"""

    if build_variant.project_name is None:
        build_dir = os.path.basename(SOURCE_ROOT)
    else:
        build_dir = os.path.basename(build_variant.project_name)

    if build_variant.toolset is not None:
        build_dir += f"_{build_variant.toolset}"

    if build_variant.cxxstd is not None:
        build_dir += f"_std{build_variant.cxxstd}"

    if build_variant.variant is not None:
        if build_variant.variant == "release":
            build_dir += f"_{build_variant.variant}"

    addr = build_variant.address_model
    if addr is not None:
        if addr == "32":
            build_dir += "_x86"

    if build_variant.link is not None:
        if build_variant.link == "shared":
            build_dir += f"_{build_variant.link}"

    return build_dir


def build_variant_to_build_dir(build_variant: BuildVariant):
    """Translates a build variant object into a named build directory to invoke CMake in"""

    fragment = build_variant_to_build_dir_fragment(build_variant)
    return os.path.join(BUILD_ROOT, fragment)


def toolset_to_cxx_compiler(toolset):
    """Used to map toolsetes to something CMake can understand"""

    if toolset.startswith("clang-"):
        return toolset.replace("clang-", "clang++-")

    if toolset.startswith("gcc-"):
        return toolset.replace("gcc-", "g++-")

    return None


def variant_to_build_type(variant):
    """Transforms a variant to something CMake understands"""

    if variant == "debug":
        return "Debug"

    if variant == "release":
        return "Release"

    return None


def build_variant_to_cmake_config_cmd(
    build_variant: BuildVariant, build_dir: str, msvc_toolset
):
    """Programmatically generate the proper arguments to pass to CMake's configure phase"""

    fragment = build_variant_to_build_dir_fragment(build_variant)

    os.makedirs(build_dir, exist_ok=True)
    toolchain_file = os.path.join(build_dir, "toolchain.cmake")

    with open(toolchain_file, "w", encoding="utf-8") as file:
        config_args = [
            CMAKE_PATH,
            "-S",
            SOURCE_ROOT,
            "-B",
            build_dir,
            "-G",
            "Ninja",
            f"-DCMAKE_MAKE_PROGRAM={NINJA_PATH}",
            f"-DCMAKE_NINJA_OUTPUT_PATH_PREFIX={fragment}",
            "-DCMAKE_SUPPRESS_REGENERATION=ON",
            f"-DC2_BUILD_ROOT={BUILD_ROOT}",
            f"-DCMAKE_TOOLCHAIN_FILE={toolchain_file}",
        ]

        file.writelines(
            [
                "set(BUILD_TESTING ON)\n",
                "set(CMAKE_EXPORT_COMPILE_COMMANDS ON)\n",
            ]
        )

        if build_variant.toolset is not None:
            if is_windows():
                toolchain = msvc_toolset

                cl = toolchain["cl"]
                cxx = cl
                if cxx.endswith("clang++.exe"):
                    cc = cxx.replace("clang++.exe", "clang.exe")
                else:
                    cc = cxx

                file.writelines(
                    [
                        f'set(CMAKE_C_COMPILER "{cc}")\n',
                        f'set(CMAKE_CXX_COMPILER "{cxx}")\n',
                        f'set(CMAKE_RC_COMPILER "{toolchain['rc']}")\n',
                        f'set(CMAKE_MT "{toolchain['mt']}")\n',
                    ]
                )

                # only cl.exe is deficient in that it requires being manually told where the stdlib header are
                # clang-cl seems perfectly capable of locating the headers on its own
                if not build_variant.toolset in ["clang"]:
                    libpaths = (
                        " ".join(
                            [
                                f'/LIBPATH:"{libpath}"'
                                for libpath in toolchain["libpath"]
                            ]
                        )
                        .replace("\\", "\\\\")
                        .replace('"', '\\"')
                    )
                    include_dirs = toolchain["include"]
                    file.writelines(
                        [
                            f'set(CMAKE_C_STANDARD_INCLUDE_DIRECTORIES "{';'.join(include_dirs).replace('\\', '\\\\')}")\n',
                            f'set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES "{';'.join(include_dirs).replace('\\', '\\\\')}")\n',
                            f'set(CMAKE_EXE_LINKER_FLAGS_INIT "{libpaths}")\n',
                            f'set(CMAKE_SHARED_LINKER_FLAGS_INIT "{libpaths}")\n',
                            # TODO: someday see if we can it to work this way
                            # it seems like CMake creates on giant -LIBPATH:<path> that exceeds the 256 byte maximum
                            #
                            # f'set(CMAKE_C_STANDARD_LINK_DIRECTORIES "{':'.join(libpaths).replace('\\', '\\\\')}")\n',
                            # f'set(CMAKE_CXX_STANDARD_LINK_DIRECTORIES "{':'.join(libpaths).replace('\\', '\\\\')}")\n',
                        ]
                    )
            else:
                toolchain = None
                cxx_compiler = toolset_to_cxx_compiler(build_variant.toolset)
                file.writelines(
                    [
                        f'set(CMAKE_C_COMPILER "{build_variant.toolset}")\n',
                        f'set(CMAKE_CXX_COMPILER "{cxx_compiler}")\n',
                    ]
                )
        else:
            raise ValueError("a toolset must be specified")

        if build_variant.variant is not None:
            build_type = variant_to_build_type(build_variant.variant)
            file.write(f"set(CMAKE_BUILD_TYPE {build_type})\n")
        else:
            file.write("set(CMAKE_BUILD_TYPE Debug)\n")

        if build_variant.cxxstd is not None:
            cxxstd = build_variant.cxxstd
            file.write(f"set(CMAKE_CXX_STANDARD {cxxstd})\n")

        if build_variant.link == "shared":
            file.write("set(BUILD_SHARED_LIBS ON)\n")
        elif build_variant.link == "static":
            file.write("set(BUILD_SHARED_LIBS OFF)\n")
        elif build_variant.link is not None:
            raise ValueError(
                f"invalid link type value {build_variant.link}. Should be static or shared"
            )
        else:
            file.write("set(BUILD_SHARED_LIBS OFF)\n")

        if is_windows():
            assert toolchain is not None
            cxxflags = []
            if (
                build_variant.toolset.startswith("msvc-")
                or build_variant.toolset == "clang-win"
            ):
                cxxflags.append("/bigobj")
        else:
            cxxflags = []

        if build_variant.address_model == "32":
            if not is_windows():
                cxxflags.append("-m32")

        if ASAN:
            if is_windows():
                if build_variant.toolset == "clang":
                    # TODO: see if we can someday remove this
                    file.write('set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")\n')
                    cxxflags.append("-fsanitize=address")
                elif build_variant.toolset.startswith("msvc-"):
                    cxxflags.append("/fsanitize=address")
                    cxxflags.append("/Zi")
                else:
                    raise NotImplementedError()
            else:
                cxxflags.append("-fsanitize=address")

        if UBSAN:
            if is_windows():
                if not ASAN:
                    file.write('set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")\n')

                if build_variant.toolset == "clang":
                    cxxflags.append("-fsanitize=undefined")
                    cxxflags.append("-fno-sanitize-recover=undefined")
                elif build_variant.toolset.startswith("msvc-"):
                    raise ValueError(
                        "cl.exe does not support ubsan, only asan is supported"
                    )
                else:
                    raise NotImplementedError()
            else:
                cxxflags.append("-fsanitize=undefined")
                cxxflags.append("-fno-sanitize-recover=undefined")

        if len(cxxflags) > 0 or CXXFLAGS is not None:
            if CXXFLAGS is not None:
                cxxflags.append(CXXFLAGS)

            init_flags = " ".join(cxxflags)

            if is_windows():
                init_flags = init_flags.replace("\\", "\\\\").replace('"', '\\"')

            file.writelines(
                [
                    f'set(CMAKE_CXX_FLAGS_INIT "{init_flags}")\n',
                    f'set(CMAKE_C_FLAGS_INIT "{init_flags}")\n',
                ]
            )

        if build_variant.toolchain_file is not None:
            toolchain_file = os.path.abspath(build_variant.toolchain_file)
        elif CMAKE_TOOLCHAIN_FILE is not None:
            toolchain_file = CMAKE_TOOLCHAIN_FILE

        if is_windows():
            toolchain_file = toolchain_file.replace('\\', '/')

        file.write(f'include("{toolchain_file}")')

    return config_args


def build_variant_to_cmake_build_args(build_variant: BuildVariant, build_dir: str):
    """Programmatically generate the proper arguments to pass to CMake's build phase"""

    build_args = [
        CMAKE_PATH,
        "--build",
        build_dir,
        "--target",
        "tests",
    ]

    if NUM_JOBS:
        build_args.append(f"-j{NUM_JOBS}")

    if build_variant.variant is not None:
        build_type = variant_to_build_type(build_variant.variant)
        build_args.append(f"--config {build_type}")
    else:
        build_args.append("--config Debug")

    return build_args


def launch_cmake_configure(build_variant: BuildVariant, toolsets):
    """ "Launches a child CMake processes that begins configuring for the given build variant"""

    build_dir = build_variant_to_build_dir(build_variant)
    cmake_cache_path = os.path.join(build_dir, "CMakeCache.txt")
    if os.path.exists(cmake_cache_path):
        # this makes sure that if a user changes the cxxflags, we always get a fresh build
        # with correct flags
        os.remove(cmake_cache_path)

    if is_windows():
        assert build_variant.toolset is not None

        if build_variant.toolset.startswith("msvc-") or build_variant.toolset in [
            "clang-win",
            "clang",
        ]:
            if build_variant.address_model == "32":
                arch = "x86"
            else:
                arch = "amd64"
        else:
            raise ValueError(f'invalid toolset specified: "{build_variant.toolset}"')

        toolset = toolsets[build_variant.toolset.replace("msvc-", "")][arch]
    else:
        toolset = None

    cmake_config_cmd = build_variant_to_cmake_config_cmd(
        build_variant, build_dir, toolset
    )

    print("cmake configuration command is:")
    print(" ".join(cmake_config_cmd))
    print("--------------------------------------------------------------------")

    process = subprocess.Popen(
        cmake_config_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    return process


def generate_msvc_toolset(arch, msvc_toolset, toolsets):
    """Runs a batch-local version of vcvarsall with the appropriate args to probe for all required paths to build a working toolchain"""

    filename = os.path.join(
        BUILD_ROOT, f"vcvars_env_{arch}_{msvc_toolset.replace('.', '')}.txt"
    )

    if msvc_toolset in ["clang-win", "clang"]:
        vcvars_ver = None
    else:
        vcvars_ver = msvc_toolset

    get_vcvars_cmd = ["get_vcvars.bat", f"-out={filename}", arch]
    if WINSDK_VERSION is not None:
        get_vcvars_cmd.append(WINSDK_VERSION)

    if vcvars_ver is not None:
        get_vcvars_cmd.append(f"-vcvars_ver={vcvars_ver}")

    print(f"going to run vcvars cmd: {' '.join(get_vcvars_cmd)}")

    subprocess.run(
        get_vcvars_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )

    with open(filename, mode="r", encoding="utf-8") as file:
        text = file.read().splitlines()
        print(text)

        if toolsets.get(msvc_toolset) is None:
            toolsets[msvc_toolset] = {"amd64": {}, "x86": {}}

        p = toolsets[msvc_toolset][arch]
        for line in text:
            if (
                not msvc_toolset in ["clang-win", "clang"]
                and line.endswith("cl.exe")
                and p.get("cl") is None
            ):
                p["cl"] = line.replace("\\", "/")

            if (
                msvc_toolset == "clang-win"
                and line.endswith("clang-cl.exe")
                and p.get("cl") is None
            ):
                p["cl"] = line.replace("\\", "/")

            if (
                msvc_toolset == "clang"
                and line.endswith("clang++.exe")
                and p.get("cl") is None
            ):
                p["cl"] = line.replace("\\", "/")

            if line.endswith("rc.exe") and p.get("rc") is None:
                p["rc"] = line.replace("\\", "/")

            if line.endswith("mt.exe") and p.get("mt") is None:
                p["mt"] = line.replace("\\", "/")

            if line.startswith("INCLUDE="):
                includes = line.split("=")
                include_paths = includes[1].split(";")
                includes = []
                includes += include_paths

                p["include"] = includes

            if line.startswith("LIB="):
                libs = line.split("=")
                libs = libs[1].split(";")
                p["libpath"] = libs

        print("----------------------------------------")
        print("completed building toolset database file")


def configure_project(build_variants: list[BuildVariant]):
    """Configures the specified library in parallel"""

    if NO_CONFIGURE:
        print("skipping CMake configuration step")
        return

    toolsets = {}
    if is_windows():
        msvc_toolsets = list(
            set(
                [
                    build_variant.toolset.replace("msvc-", "")
                    for build_variant in build_variants
                ]
            )
        )

        has_32_bit = any(
            build_variant.address_model == "32" for build_variant in build_variants
        )
        has_64_bit = any(
            build_variant.address_model == "64" or build_variant.address_model is None
            for build_variant in build_variants
        )

        for msvc_toolset in msvc_toolsets:
            print(f"gathering toolset info for msvc-{msvc_toolset}")
            if has_32_bit:
                arch = "x86"
                generate_msvc_toolset(arch, msvc_toolset, toolsets)

            if has_64_bit:
                arch = "amd64"
                generate_msvc_toolset(arch, msvc_toolset, toolsets)

        print("built the following toolsets for msvc")
        pprint.pprint(toolsets, width=256)

    cmake_config_procs = []
    for idx, build_variant in enumerate(build_variants):
        print(f"launching configuration job {idx + 1} of {len(build_variants)}")
        proc = launch_cmake_configure(build_variant, toolsets)
        cmake_config_procs.append(proc)

    configure_failed = False

    # pipes = []
    outputs = [["", ""]] * len(cmake_config_procs)

    for i, config_proc in enumerate(cmake_config_procs):
        if config_proc.poll() is None:
            try:
                stdout, stderr = config_proc.communicate(input=None, timeout=0.25)
                outputs[i][0] += stdout
                outputs[i][1] += stderr
            except subprocess.TimeoutExpired:
                continue

        # pipes.append((stdout, stderr))

    for i, config_proc in enumerate(cmake_config_procs):
        stdout, stderr = config_proc.communicate()
        outputs[i][0] += stdout
        outputs[i][1] += stderr
        config_proc.wait()

        stdout, stderr = outputs[i]
        if stderr:
            print("cmake configuration wrote the following to stderr:")
            print(stdout)
            print(stderr)

        if config_proc.returncode != 0:
            configure_failed = True

    if configure_failed:
        print("CMake configuration failed, exiting now")
        sys.exit(1)

    print("configuration complete")

    print("patching ninja files")
    builds_dir_fragments = [
        build_variant_to_build_dir_fragment(bv) for bv in build_variants
    ]
    txt = None
    for fragment in builds_dir_fragments:
        ninja_file = os.path.join(BUILD_ROOT, fragment, "build.ninja")

        with open(ninja_file, mode="r", encoding="utf-8") as file:
            txt = file.read()

        updated_txt = txt.replace(
            "cmake_object_order_depends_target_",
            f"cmake_object_order_depends_target_{fragment}",
        )

        with open(ninja_file, mode="w", encoding="utf-8") as file:
            file.write(updated_txt)

    print("completed patching ninja")


def parse_args():
    """Parse CLI args and form the build variants array"""

    parser = argparse.ArgumentParser(
        description="Parse all build options and assemble the matrix."
    )

    parser.add_argument(
        "command",
        type=str,
        help="Main driver command. Either just `build` or `test`. `test` implies `build` but also "
        "invokes `ctest` for each generated build directory.",
    )

    parser.add_argument(
        "--source-dir",
        dest="source_dir",
        type=str,
        help="Name of the library to build tests for.",
    )

    parser.add_argument(
        "--cmake-path",
        type=str,
        help="Path to a working CMake executable.",
        dest="cmake_path",
    )

    parser.add_argument(
        "--ninja-path",
        type=str,
        help="Path to a working Ninja executable.",
        dest="ninja_path",
    )

    parser.add_argument(
        "-j",
        type=int,
        dest="jobs",
        help="Number of jobs used to build with CMake.",
    )

    parser.add_argument(
        "--target",
        type=str,
        help="Name of the CMake target to be used in the `cmake --build <build_dir> --target <target>` call.",
    )

    parser.add_argument(
        "--cxxstd",
        type=str,
        help="A comma-separated list of C++ standard versions (e.g., 'cxxstd=11,17,20').",
    )

    parser.add_argument(
        "--toolset",
        type=str,
        help="A comma-separated list of C++ toolchains to use (e.g. toolset=gcc-14,clang-19 "
        "[no '++' required])",
    )

    parser.add_argument(
        "--variant",
        type=str,
        help="A comma-separated list of C++ build types (e.g variant=debug,release or "
        "variant=release)",
    )

    parser.add_argument(
        "--address-model",
        type=str,
        help="A comma-separated list of architectures (e.g. address-model=32,64)",
        dest="address_model",
    )

    parser.add_argument(
        "--link",
        type=str,
        help="A comma-separated list of link models (e.g. link=static,shared)",
    )

    parser.add_argument(
        "--ubsan", action="store_true", help="Build with -fsanitize=undefined"
    )

    parser.add_argument(
        "--asan",
        action="store_true",
        help="Build with -fsanitize=address",
    )

    parser.add_argument(
        "--skip-configure",
        action="store_true",
        help="Skip the CMake configuration step",
        dest="no_cmake",
    )

    parser.add_argument(
        "--cxxflags",
        type=str,
        help="Add custom compiler options that will be added to "
        "`CMAKE_CXX_FLAGS_INIT` during configure time",
    )

    parser.add_argument(
        "--ctestflags",
        type=str,
        help="Additional arguments to be passed to ctest during test running",
    )

    parser.add_argument(
        "--winsdk-version",
        type=str,
        dest="winsdk_version",
        help='Version of the Windows SDK to use (e.g. 10.0.22621.0). Commonly found in: "C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.22621.0"',
    )

    parser.add_argument(
        "--cmake-toolchain-file",
        type=str,
        dest="cmake_toolchain_file",
        help="Path to the CMake toolchain file that will be common to all builds generated."
    )

    parser.add_argument(
        "--toolchains",
        type=str,
        help="Path to a JSON file containing an array of build variants. This option will override all over the build matrix generation options specified.",
    )

    args = parser.parse_args()

    cxxstds = []
    toolsets = []
    variants = []
    address_models = []
    links = []

    if args.command:
        command = args.command
        if command not in ("build", "test"):
            raise ValueError(
                'The only permitted sub-commands for c2.py are: "build" or "test".'
            )

        global COMMAND_MODE
        COMMAND_MODE = command
    else:
        raise ValueError("Must specify a build command such as `build` or `test.")

    if args.source_dir:
        global SOURCE_ROOT
        SOURCE_ROOT = os.path.abspath(args.source_dir)

    if args.cmake_path:
        global CMAKE_PATH
        CMAKE_PATH = shutil.which(args.cmake_path)

    if args.ninja_path:
        global NINJA_PATH
        NINJA_PATH = shutil.which(args.ninja_path)

    if args.jobs:
        global NUM_JOBS
        NUM_JOBS = args.jobs

    if args.winsdk_version:
        global WINSDK_VERSION
        WINSDK_VERSION = args.winsdk_version

    if args.cxxstd:
        result = args.cxxstd.split(",")
        cxxstds += result
    else:
        cxxstds.append(None)

    if args.toolset:
        result = args.toolset.split(",")
        toolsets += result
    else:
        toolsets.append(None)

    if args.variant:
        result = args.variant.split(",")
        variants += result
    else:
        variants.append(None)

    if args.address_model:
        result = args.address_model.split(",")
        address_models += result
    else:
        address_models.append(None)

    if args.link:
        result = args.link.split(",")

        if len(result) != len(list(set(result))):
            raise ValueError(
                "Invalid link value. Should be of the form"
                ": --link=static,shared or --link=shared."
            )

        for r in result:
            if r not in ("static", "shared"):
                raise ValueError(
                    f"{r} is an invalid link type, must be static or shared"
                )

        links += result
    else:
        links.append(None)

    if args.asan:
        global ASAN
        ASAN = True

    if args.ubsan:
        global UBSAN
        UBSAN = True

    if args.no_cmake:
        global NO_CONFIGURE
        NO_CONFIGURE = True

    if args.cmake_toolchain_file:
        global CMAKE_TOOLCHAIN_FILE
        CMAKE_TOOLCHAIN_FILE = os.path.abspath(args.cmake_toolchain_file)

    if args.cxxflags:
        global CXXFLAGS
        CXXFLAGS = args.cxxflags

    if args.ctestflags:
        global CTESTFLAGS
        CTESTFLAGS = args.ctestflags

    if args.target:
        global TARGET
        TARGET = args.target

    if args.toolchains:
        with open(os.path.abspath(args.toolchains), mode="r", encoding="utf-8") as file:
            build_dicts = json.load(file)
    else:
        configs = {
            "cxxstd": cxxstds,
            "toolset": toolsets,
            "variant": variants,
            "address_model": address_models,
            "link": links,
        }

        config_perms = list(itertools.product(*configs.values()))
        build_dicts = [dict(zip(configs.keys(), values)) for values in config_perms]

    build_variants = []
    for build_dict in build_dicts:
        build_variant = BuildVariant(
            cxxstd=build_dict.get("cxxstd"),
            toolset=build_dict.get("toolset"),
            variant=build_dict.get("variant"),
            address_model=build_dict.get("address_model"),
            link=build_dict.get("link"),
            toolchain_file=build_dict.get("toolchain_file"),
            project_name=build_dict.get("project_name"),
        )

        build_variants.append(build_variant)

    return build_variants


def build_with_driver_ninja_file(build_variants):
    """Write the main driving ninja.build that users will use for building the project"""

    builds_dir_fragments = [
        build_variant_to_build_dir_fragment(bv) for bv in build_variants
    ]

    with open(
        os.path.join(BUILD_ROOT, "build.ninja"), mode="w", encoding="utf-8"
    ) as file:
        for build_dir in builds_dir_fragments:
            file.write(f"subninja {build_dir}/build.ninja\n")
        file.write("\n")

        ts = [os.path.join(path, TARGET) for path in builds_dir_fragments]
        file.write(f"build all: phony {' '.join(ts)}\n")

        cs = [os.path.join(path, "clean") for path in builds_dir_fragments]
        file.write(f"build clean: phony {' '.join(cs)}\n")

        file.write("\n")
        file.write("default all")
        file.write("\n")

    assert NINJA_PATH is not None

    ninja_cmd = [NINJA_PATH]
    if NUM_JOBS is not None:
        ninja_cmd.append(f"-j{NUM_JOBS}")

    subprocess.run(ninja_cmd, cwd=BUILD_ROOT, check=True)
    return


def build_ctest_testfile(build_variants):
    """Write the main CTestTestfile.cmake that will be responsible for building the global test list for ctest"""

    build_dir_fragments = [
        build_variant_to_build_dir_fragment(bv) for bv in build_variants
    ]

    with open(
        os.path.join(BUILD_ROOT, "CTestTestfile.cmake"), mode="w", encoding="utf-8"
    ) as file:
        file.writelines(
            "\n".join([f'subdirs("{fragment}")' for fragment in build_dir_fragments])
        )
        file.write("\n")


def run_tests():
    """Execute CTest on the generated CTestTestile.cmake"""

    assert CMAKE_PATH is not None

    cmake_bin_dir = os.path.dirname(CMAKE_PATH)
    ctest_cmd = [
        os.path.join(cmake_bin_dir, "ctest"),
        "--parallel",
        "--output-on-failure",
        "--no-tests=error",
        "--stop-on-failure",
        "--schedule-random",
    ]

    subprocess.run(ctest_cmd, cwd=BUILD_ROOT, check=True)


def setup_cmake():
    """Ensure the user has given us a path to CMake or we can find it."""

    global CMAKE_PATH
    if CMAKE_PATH is None:
        CMAKE_PATH = shutil.which("cmake")

    if CMAKE_PATH is None:
        raise ValueError(
            "no valid CMake binary was specified. Add it to your PATH or via --cmake-path."
        )

    print(f"using the cmake binary at: {CMAKE_PATH}")


def setup_ninja():
    """Ensure the user has given us a path to Ninja or we can find it"""

    global NINJA_PATH
    if NINJA_PATH is None:
        NINJA_PATH = shutil.which("ninja")

    if NINJA_PATH is None:
        raise ValueError(
            "no valid Ninja binary was specified. Add it to your PATH or via --ninja-path."
        )

    print(f"using the ninja binary at: {NINJA_PATH}")


def init():
    """Main entry for bulk-building via CMake"""

    print("starting c2.py script")

    build_variants = parse_args()
    setup_cmake()
    setup_ninja()

    # pprint.pp(build_variants)

    os.makedirs(BUILD_ROOT, exist_ok=True)
    configure_project(build_variants)
    build_with_driver_ninja_file(build_variants)
    build_ctest_testfile(build_variants)

    if COMMAND_MODE == "test":
        run_tests()


if __name__ == "__main__":
    init()
