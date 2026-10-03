"""Optional native MSVC x64 build; no changes to the caller's environment."""
import functools
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def installation_from_manifest(root):
    manifest = root / "debug-tool-manifest.json"
    if not manifest.exists():
        return None
    try:
        entries = json.loads(manifest.read_text(encoding="utf-8-sig")).get("results", [])
        for entry in entries:
            if entry.get("name") not in ("cl.exe", "link.exe", "dumpbin.exe"):
                continue
            path = Path(entry.get("path") or "")
            if not path.is_file():
                continue
            for parent in path.parents:
                if parent.name == "VC":
                    return parent.parent
    except (OSError, ValueError):
        pass
    return None


@functools.lru_cache(maxsize=1)
def discover(root):
    if sys.platform != "win32":
        return None
    root = Path(root)
    install = installation_from_manifest(root)
    if install is None:
        vswhere = shutil.which("vswhere.exe")
        if not vswhere:
            candidate = Path(os.environ.get("ProgramFiles(x86)", "")) / \
                "Microsoft Visual Studio/Installer/vswhere.exe"
            vswhere = str(candidate) if candidate.is_file() else None
        if vswhere:
            proc = subprocess.run([vswhere, "-latest", "-products", "*", "-requires",
                                   "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                                   "-property", "installationPath"],
                                  capture_output=True, text=True, timeout=30, check=True)
            if proc.stdout.strip():
                install = Path(proc.stdout.strip())
    if install is not None:
        vcvars = install / "VC/Auxiliary/Build/vcvarsall.bat"
        if not vcvars.is_file():
            raise RuntimeError("MSVC found but vcvarsall.bat is missing")
        command = f'"{os.environ.get("COMSPEC", "cmd.exe")}" /d /s /c ""{vcvars}" x64 >nul && set"'
        proc = subprocess.run(command,
                              capture_output=True, text=True, errors="replace",
                              timeout=60, check=True)
        env = dict(os.environ)
        for line in proc.stdout.splitlines():
            key, sep, value = line.partition("=")
            if sep and key:
                env[key.upper()] = value
    elif os.environ.get("VSCMD_ARG_TGT_ARCH", "").lower() == "x64":
        env = {k.upper(): v for k, v in os.environ.items()}
    else:
        return None
    found = {name: shutil.which(name + ".exe", path=env.get("PATH", ""))
             for name in ("cl", "link", "rc")}
    if not all(found.values()):
        raise RuntimeError("MSVC detected but x64 compiler/linker or Windows SDK rc.exe is missing")
    return env, found


def build(config, project):
    target, directory, _, _, archive, _ = config
    directory = project.effective_out_dir(directory)
    out = project.BASE_DIR / directory
    out.mkdir(parents=True, exist_ok=True)
    try:
        found = discover(project.BASE_DIR)
        if found is None:
            raise RuntimeError("Native MSVC x64 toolchain not found")
        env, tools = found
        if project.SANITIZER_MODE or project.PGO_MODE:
            raise RuntimeError("MSVC comparison builds do not accept Clang sanitizer/PGO options")
        warnings = []
        build_log = out / "build.log"
        build_log.write_text("", encoding="utf-8")

        def run(command, cwd=project.BASE_DIR):
            proc = subprocess.run(command, cwd=cwd, env=env, capture_output=True)
            output = (proc.stdout + proc.stderr).decode(errors="replace")
            with build_log.open("a", encoding="utf-8") as log:
                log.write(output)
            proc.check_returncode()
            warnings.extend(line for line in output.splitlines() if "warning " in line)
            return output

        flags = ["/nologo", "/std:c++20", "/O2", "/Ob3", "/Oi", "/MT", "/Zi",
                 "/fp:strict", "/GR-", "/GS-", "/EHsc", "/W3", "/utf-8",
                 "/DUNICODE", "/D_UNICODE", "/D_WIN32_WINNT=0x0A00",
                 "/DDISABLE_SEH", "/D_CRT_SECURE_NO_WARNINGS", "/I" + str(project.SRC_DIR),
                 "/Fd" + str(out / "compile.pdb")]
        flags += ["/D" + arg[2:] for arg in project.version_defines(directory) + project.EXTRA_DEFINES]
        objects = []
        for source in project.SRC_FILES_WINDOWS:
            obj = out / (Path(source).stem + ".obj")
            # Every object shares /arch:AVX2: header inline functions become
            # COMDATs the linker may take from any object, so a file-wide
            # /arch:AVX512 could leak EVEX code into AVX2-only paths. MSVC emits
            # the explicit _mm512 intrinsics without /arch:AVX512.
            extra = ["/arch:AVX2", "/GL"]
            if source in project.build_kernels.KERNEL_SOURCES:
                extra = ["/arch:AVX2", "/GL-"]
            elif source.endswith("CpuGuard.cpp"):
                # Never allow AVX code or LTCG into the pre-CRT CPU guard.
                extra = ["/GL-", "/DSS_BUILD_V3"]
            run([tools["cl"], *flags, *extra, "/c", source, "/Fo" + str(obj)])
            objects.append(str(obj))
        res = out / "resource.res"
        run([tools["rc"], "/nologo", "/fo", str(res), "resource.rc"], project.RESOURCE_RC.parent)
        exe = out / "ShaderStress.exe"
        run([tools["link"], "/nologo", *objects, str(res), "/out:" + str(exe),
             "/subsystem:windows", "/entry:ShaderStressGuardedEntry", "/LTCG",
             "/debug:full", "/pdb:" + str(out / "ShaderStress.pdb"),
             "/opt:ref", "/opt:icf", "/incremental:no",
             "kernel32.lib", "user32.lib", "gdi32.lib", "dwmapi.lib", "shcore.lib",
             "shell32.lib", "ole32.lib", "oleaut32.lib", "dbghelp.lib", "winmm.lib",
             "advapi32.lib"])
        launcher = out / "ShaderStress.com"
        run([tools["cl"], "/nologo", "/O2", "/MT", "/DUNICODE", "/D_UNICODE",
             "/D_CRT_SECURE_NO_WARNINGS", str(project.CLI_LAUNCHER_SOURCE),
             "/Fo" + str(out / "cli_launcher.obj"), "/Fe" + str(launcher),
             "/link", "/subsystem:console", "/incremental:no"])
        project.set_pe_checksum(exe)
        project.build_power_reader(out)
        project.log("MSVC: /O2 /fp:strict /arch:AVX2, non-LTCG synthetic kernels, baseline CPU guard")
        return True, target, directory, archive, warnings
    except subprocess.CalledProcessError as error:
        # cl.exe writes diagnostics to stdout, unlike Clang.
        output = ((error.stdout or b"") + (error.stderr or b"")).decode(errors="replace")
        errors = [line for line in output.splitlines() if "error" in line.lower()]
        return False, target, directory, "\n".join(errors[:15]) or output[-1500:], []
    except (OSError, RuntimeError) as error:
        return False, target, directory, str(error), []
