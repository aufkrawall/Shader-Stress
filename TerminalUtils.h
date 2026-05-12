#ifndef TERMINAL_UTILS_H
#define TERMINAL_UTILS_H

#if defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS)

bool IsRunningInTerminal();
bool TrySpawnTerminal(int argc, char* argv[]);
void ShowTerminalRequiredError();
bool ShouldSkipTerminalSpawn(int argc, char* argv[]);

#endif

#endif
