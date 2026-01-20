#include "Common.h"

#if defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS)

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <signal.h>

static bool TrySpawnInTerminalEmulator(int argc, char* argv[]) {
    const char* selfPath = argv[0];
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
        for (int i = 0; i < 3; ++i) {
            pid_t pid = fork();
            if (pid == 0) {
                if (term.needsHoldArg) {
                    execlp(term.cmd, term.cmd, "--hold", "-e", selfPath, (char*)NULL);
                } else {
                    execlp(term.cmd, term.cmd, "--", selfPath, (char*)NULL);
                }
                _exit(127);
            } else if (pid > 0) {
                int status;
                waitpid(pid, &status, WNOHANG);
                if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
                    continue;
                }
                return true;
            }
        }
    }

    return false;
}

static bool TrySpawnInVirtualTerminal(int argc, char* argv[]) {
    const char* selfPath = argv[0];

    for (int vt = 1; vt <= 12; ++vt) {
        pid_t pid = fork();
        if (pid == 0) {
            setsid();
            execlp("openvt", "openvt", "-s", "-w", "--", selfPath, (char*)NULL);
            _exit(127);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, WNOHANG);
            if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
                continue;
            }
            return true;
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
