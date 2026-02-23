#include "Common.h"

#if defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS)

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

// Maximum time to wait for terminal spawn (milliseconds)
constexpr int SPAWN_TIMEOUT_MS = 5000;
constexpr int POLL_INTERVAL_US = 50000; // 50ms

static std::vector<char*> BuildSpawnArgs(const char* launcher, bool needsHoldArg,
                                         int argc, char* argv[]) {
    std::vector<char*> args;
    args.reserve(static_cast<size_t>(argc) + 6);
    args.push_back(const_cast<char*>(launcher));
    if (needsHoldArg) {
        args.push_back(const_cast<char*>("--hold"));
        args.push_back(const_cast<char*>("-e"));
    } else {
        args.push_back(const_cast<char*>("--"));
    }
    args.push_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        args.push_back(argv[i]);
    }
    args.push_back(nullptr);
    return args;
}

static std::vector<char*> BuildOpenVtArgs(int argc, char* argv[]) {
    std::vector<char*> args;
    args.reserve(static_cast<size_t>(argc) + 7);
    args.push_back(const_cast<char*>("openvt"));
    args.push_back(const_cast<char*>("-s"));
    args.push_back(const_cast<char*>("-w"));
    args.push_back(const_cast<char*>("--"));
    args.push_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        args.push_back(argv[i]);
    }
    args.push_back(nullptr);
    return args;
}

static bool TrySpawnInTerminalEmulator(int argc, char* argv[]) {
    const char* display = getenv("DISPLAY");
    const char* wayland = getenv("WAYLAND_DISPLAY");

    if (!display && !wayland) {
        return false;
    }

    struct TerminalCmd {
        const char* name;
        const char* cmd;
        bool needsHoldArg;
    };

    TerminalCmd terminals[] = {
        {"konsole", "konsole", true},
        {"gnome-terminal", "gnome-terminal", false},
        {"xfce4-terminal", "xfce4-terminal", true},
        {"xterm", "xterm", true},
    };

    for (const auto& term : terminals) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child process: try to spawn terminal
            // Redirect stdout/stderr to avoid polluting parent's output
            int devNull = open("/dev/null", O_WRONLY);
            if (devNull >= 0) {
                dup2(devNull, STDOUT_FILENO);
                dup2(devNull, STDERR_FILENO);
                close(devNull);
            }
            
            auto termArgs = BuildSpawnArgs(term.cmd, term.needsHoldArg, argc, argv);
            execvp(term.cmd, termArgs.data());
            // If we get here, execlp failed
            _exit(127);
        } else if (pid > 0) {
            // Parent: wait for child with timeout using polling
            int status;
            int waitedMs = 0;
            pid_t result;
            
            while (waitedMs < SPAWN_TIMEOUT_MS) {
                result = waitpid(pid, &status, WNOHANG);
                if (result == pid) {
                    // Child exited
                    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
                        // execlp failed, try next terminal
                        break;
                    }
                    // Child exited with other status - assume terminal spawned
                    return true;
                } else if (result == 0) {
                    // Child still running - terminal likely spawned successfully
                    // Give it a bit more time to stabilize
                    usleep(POLL_INTERVAL_US);
                    waitedMs += POLL_INTERVAL_US / 1000;
                } else {
                    // Error
                    break;
                }
            }
            
            if (result == 0) {
                // Still running after timeout - assume success
                return true;
            }
            // Otherwise try next terminal
        }
    }

    return false;
}

static bool TrySpawnInVirtualTerminal(int argc, char* argv[]) {
    for (int vt = 1; vt <= 12; ++vt) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child
            setsid();
            auto openVtArgs = BuildOpenVtArgs(argc, argv);
            execvp("openvt", openVtArgs.data());
            _exit(127);
        } else if (pid > 0) {
            // Parent: wait with timeout
            int status;
            int waitedMs = 0;
            pid_t result;
            
            while (waitedMs < SPAWN_TIMEOUT_MS) {
                result = waitpid(pid, &status, WNOHANG);
                if (result == pid) {
                    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
                        break; // Try next VT
                    }
                    return true;
                } else if (result == 0) {
                    usleep(POLL_INTERVAL_US);
                    waitedMs += POLL_INTERVAL_US / 1000;
                } else {
                    break;
                }
            }
            
            if (result == 0) {
                return true; // Still running, assume success
            }
        }
    }

    return false;
}

bool IsRunningInTerminal() {
    return isatty(STDIN_FILENO) != 0;
}

bool TrySpawnTerminal(int argc, char* argv[]) {
    if (TrySpawnInTerminalEmulator(argc, argv)) {
        return true;
    }
    if (TrySpawnInVirtualTerminal(argc, argv)) {
        return true;
    }
    return false;
}

void ShowTerminalRequiredError() {
    std::cout << "\n";
    std::cout << "==============================================\n";
    std::cout << "  ERROR: Not running in a terminal!\n";
    std::cout << "==============================================\n\n";
    std::cout << "This application requires interactive input.\n";
    std::cout << "It cannot run in the background silently.\n\n";
    std::cout << "Please run it from a terminal, or double-click\n";
    std::cout << "the application again - it should detect the\n";
    std::cout << "missing terminal and spawn one automatically.\n\n";
    std::cout << "If that fails, please run manually:\n";
    std::cout << "  ./shaderstress\n";
    std::cout << "from your terminal emulator.\n\n";
    std::cout << "For automated/scripted use, see:\n";
    std::cout << "  ./shaderstress --help\n";
    std::cout << "==============================================\n";
}

bool ShouldSkipTerminalSpawn(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--force-no-spawn") == 0) {
            return true;
        }
    }
    return false;
}

#endif
