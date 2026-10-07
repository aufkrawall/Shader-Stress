"""Host-side helpers for the manual power measurements (Windows).

- UAC self-elevation: PawnIO sensor reads (package power, effective clock,
  temperature, Vcore) need an elevated process. relaunch_elevated() starts the
  same script via ShellExecuteExW("runas") and relays its output from a log
  file (an elevated child cannot inherit a non-elevated console's pipes). With
  UAC set to elevate administrators without prompting
  (ConsentPromptBehaviorAdmin=0) this needs no interaction; otherwise Windows
  shows one consent prompt.
- Background-load checks: measurements on a busy system are confounded. Before
  a run, wait_for_quiet_system(); during the measurement window, the workload
  runs in a job object (TrackedProcess) and foreign_percent() reports the CPU
  share taken by everything else.

Unit tests exercise the pure helpers only; they never elevate or load the CPU.
"""
import codecs
import ctypes
import os
import subprocess
import sys
import time
from pathlib import Path

ELEVATED_FLAG = "--elevated-child"
ERROR_CANCELLED = 1223
WAIT_TIMEOUT = 0x102
SEE_MASK_NOCLOSEPROCESS = 0x40
SEE_MASK_NOASYNC = 0x100
SW_SHOWMINNOACTIVE = 7  # visible in the taskbar (closable), never steals focus

if sys.platform == "win32":
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong),
                    ("hwnd", wintypes.HWND), ("lpVerb", wintypes.LPCWSTR),
                    ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int),
                    ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                    ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE),
                    ("hProcess", wintypes.HANDLE)]

    class FILETIME(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

        def value(self):
            return (self.high << 32) | self.low


def is_admin():
    return sys.platform == "win32" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def child_arguments(script, argv, relay_log, stop_file):
    """Parameter string for the elevated child: same arguments plus relay paths."""
    return subprocess.list2cmdline([str(script), *argv, ELEVATED_FLAG, "--relay-log",
                                    str(relay_log), "--stop-file", str(stop_file)])


class LogRelay:
    """Copies the new bytes of a growing UTF-8 log file to a text stream."""

    def __init__(self, path, out):
        self.path, self.out, self.offset = Path(path), out, 0
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def pump(self, final=False):
        try:
            with self.path.open("rb") as f:
                f.seek(self.offset)
                data = f.read()
        except FileNotFoundError:
            data = b""
        self.offset += len(data)
        text = self.decoder.decode(data, final=final)  # keeps split UTF-8 sequences
        if text:
            self.out.write(text)
            self.out.flush()
        return text


def relaunch_elevated(script, argv, evidence_dir, cwd, out=None):
    """Runs `script argv` elevated, relays its output, returns its exit code.

    First Ctrl+C asks the child (via a stop file) to finish its current run and
    write its results; a second Ctrl+C detaches and leaves it running.
    """
    out = out or sys.stdout
    if hasattr(out, "reconfigure"):
        # A legacy console code page must not abort the relay mid-session.
        out.reconfigure(errors="replace")
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    relay_log = evidence_dir / f"elevated-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}.log"
    stop_file = relay_log.with_suffix(".stop")
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    info.lpVerb = "runas"
    info.lpFile = sys.executable
    info.lpParameters = child_arguments(script, argv, relay_log, stop_file)
    info.lpDirectory = str(cwd)
    info.nShow = SW_SHOWMINNOACTIVE
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.get_last_error()
        if error == ERROR_CANCELLED:
            raise RuntimeError("UAC elevation was declined; sensor readout needs admin rights")
        raise RuntimeError(f"UAC elevation failed (Windows error {error})")
    if not info.hProcess:
        raise RuntimeError("UAC elevation returned no process handle")
    print(f"Elevated measurement process started via UAC; output relayed from {relay_log}",
          file=out, flush=True)
    relay = LogRelay(relay_log, out)
    stop_requested = False
    try:
        while True:
            try:
                # 1 s is only the relay cadence; completion is the process handle.
                if kernel32.WaitForSingleObject(info.hProcess, 1000) != WAIT_TIMEOUT:
                    break
                relay.pump()
            except KeyboardInterrupt:
                if stop_requested:
                    print("Detached; the elevated process stops after its current run. "
                          f"Results stay in its session directory ({relay_log}).", file=out)
                    return 130
                stop_requested = True
                stop_file.write_text("stop\n", encoding="utf-8")
                print("Stop requested: the elevated process finishes its current run and "
                      "writes results (Ctrl+C again to detach).", file=out, flush=True)
        relay.pump(final=True)
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code)):
            raise RuntimeError(f"GetExitCodeProcess failed (error {ctypes.get_last_error()})")
        return code.value
    finally:
        kernel32.CloseHandle(info.hProcess)


def system_times():
    """(idle, kernel, user) CPU time of all logical CPUs in 100 ns units."""
    idle, kernel, user = FILETIME(), FILETIME(), FILETIME()
    if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel),
                                                  ctypes.byref(user)):
        raise OSError("GetSystemTimes failed")
    return idle.value(), kernel.value(), user.value()


def busy_percent(before, after):
    """System-wide CPU utilization between two system_times() readings."""
    idle = after[0] - before[0]
    total = (after[1] - before[1]) + (after[2] - before[2])  # kernel time includes idle
    if total <= 0:
        return 0.0
    return max(0.0, min(100.0, 100.0 * (total - idle) / total))


def wait_for_quiet_system(max_percent, window=3.0, attempts=10, times=system_times,
                          sleep=time.sleep):
    """Returns the background load once a `window` stays below `max_percent`.

    The window is a measurement interval, not a synchronization delay. Raises
    if the system stays busy for `attempts` windows: results would be confounded.
    """
    load = 100.0
    for _ in range(attempts):
        before = times()
        sleep(window)
        load = busy_percent(before, times())
        if load <= max_percent:
            return round(load, 1)
    raise RuntimeError(f"background CPU load {load:.1f}% stayed above {max_percent}% for "
                       f"{attempts * window:.0f} s; close other workloads (measurements would "
                       "be confounded) or raise --max-background-load")


def foreign_percent(sys_before, sys_after, own_before, own_after):
    """System CPU % used outside the measured process tree between two readings.

    sys_*: system_times() tuples; own_*: TrackedProcess.cpu_time() values (100 ns).
    With every logical CPU loaded by the workload, foreign work displaces it, so
    this share is what confounds a measurement (background spikes up to 100%).
    """
    idle = sys_after[0] - sys_before[0]
    total = (sys_after[1] - sys_before[1]) + (sys_after[2] - sys_before[2])
    if total <= 0:
        return 0.0
    foreign = total - idle - (own_after - own_before)
    return max(0.0, min(100.0, 100.0 * foreign / total))


CREATE_SUSPENDED = 0x4
JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1

if sys.platform == "win32":
    class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
        _fields_ = [("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
                    ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                    ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                    ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
                    ("ActiveProcesses", wintypes.DWORD),
                    ("TotalTerminatedProcesses", wintypes.DWORD)]


class TrackedProcess:
    """A command started suspended inside a job object (Windows).

    The job accounts the CPU time of the whole tree (ShaderStress.com launches
    ShaderStress.exe, which inherits the job), so foreign_percent() can separate
    background load from the workload. Assigning before resuming closes the race
    in which the launcher could spawn the workload outside the job.
    """

    def __init__(self, command, cwd, stdout):
        self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._k32.CreateJobObjectW.restype = wintypes.HANDLE
        self._k32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        self._k32.QueryInformationJobObject.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD))
        self._k32.CloseHandle.argtypes = (wintypes.HANDLE,)
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
        self.job = self._k32.CreateJobObjectW(None, None)
        if not self.job:
            raise OSError(f"CreateJobObjectW failed (error {ctypes.get_last_error()})")
        self.proc = None
        try:
            self.proc = subprocess.Popen(command, cwd=cwd, stdout=stdout,
                                         stderr=subprocess.STDOUT,
                                         creationflags=CREATE_SUSPENDED)
            handle = int(self.proc._handle)
            if not self._k32.AssignProcessToJobObject(self.job, handle):
                raise OSError(f"AssignProcessToJobObject failed (error {ctypes.get_last_error()})")
            status = ntdll.NtResumeProcess(handle)
            if status != 0:
                raise OSError(f"NtResumeProcess failed (NTSTATUS 0x{status & 0xFFFFFFFF:08x})")
        except BaseException:
            if self.proc is not None:
                self.proc.kill()
                self.proc.wait()
            self.close()
            raise

    def cpu_time(self):
        """User + kernel time of every process that ran in the job, 100 ns units."""
        info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        if not self._k32.QueryInformationJobObject(self.job, JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                                                   ctypes.byref(info), ctypes.sizeof(info), None):
            raise OSError(f"QueryInformationJobObject failed (error {ctypes.get_last_error()})")
        return info.TotalUserTime + info.TotalKernelTime

    def close(self):
        if self.job:
            self._k32.CloseHandle(self.job)
            self.job = None
