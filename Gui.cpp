// Gui.cpp - Windows GDI GUI, button handling, painting
#include "Common.h"
#include <CommCtrl.h>
#include <sstream>

// GDI Resources
HFONT g_Font = nullptr;
HBRUSH g_BgBrush = nullptr;
HBRUSH g_BtnActive = nullptr;
HBRUSH g_BtnInactive = nullptr;
HBRUSH g_BtnDisabled = nullptr;
static HBRUSH s_EditBrush = nullptr;

// Backbuffer resources
static HDC s_memDC = nullptr;
static HBITMAP s_memBM = nullptr;
static int s_width = 0, s_height = 0;

// Forward declarations
void ShowVerifyDialog(HWND parent);

void InitGDI() {
  g_Font = CreateFontW(-(int)(16 * g_Scale), 0, 0, 0, FW_NORMAL, 0, 0, 0,
                       DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
  g_BgBrush = CreateSolidBrush(RGB(20, 20, 20));
  g_BtnActive = CreateSolidBrush(RGB(60, 100, 160));
  g_BtnInactive = CreateSolidBrush(RGB(50, 50, 50));
  g_BtnDisabled = CreateSolidBrush(RGB(30, 30, 30));
  s_EditBrush = CreateSolidBrush(RGB(40, 40, 40));
}

void CleanupGDI() {
  DeleteObject(g_Font);
  DeleteObject(g_BgBrush);
  DeleteObject(g_BtnActive);
  DeleteObject(g_BtnInactive);
  DeleteObject(g_BtnDisabled);
  DeleteObject(s_EditBrush);
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  if (m == WM_DESTROY) {
    if (s_memDC)
      DeleteDC(s_memDC);
    if (s_memBM)
      DeleteObject(s_memBM);
    g_App.running = false;
    g_App.quit = true;
    PostQuitMessage(0);
    return 0;
  }
  if (m == WM_PAINT) {
    PAINTSTRUCT ps;
    BeginPaint(h, &ps);
    RECT rc;
    GetClientRect(h, &rc);

    if (rc.right != s_width || rc.bottom != s_height || !s_memDC) {
      if (s_memDC) {
        DeleteDC(s_memDC);
        DeleteObject(s_memBM);
      }
      s_memDC = CreateCompatibleDC(ps.hdc);
      s_memBM = CreateCompatibleBitmap(ps.hdc, rc.right, rc.bottom);
      SelectObject(s_memDC, s_memBM);
      s_width = rc.right;
      s_height = rc.bottom;
    }

    // Auto-clipboard Check (polled during Paint for simplicity via Timer)
    static std::wstring s_lastHash;
    static uint64_t s_notifyTime = 0;
    std::wstring currentHash = g_App.GetBenchHash();
    if (!currentHash.empty() && currentHash != s_lastHash) {
      s_lastHash = currentHash;

      std::wstringstream ss;
      // Use thread-safe snapshot to avoid race conditions
      auto historySnapshot = g_App.GetLogHistorySnapshot();
      for (const auto &line : historySnapshot) {
        ss << line << L"\n";
      }
      std::wstring fullText = ss.str();

      if (OpenClipboard(h)) {
        EmptyClipboard();
        size_t bytes = (fullText.size() + 1) * sizeof(wchar_t);
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (hMem) {
          memcpy(GlobalLock(hMem), fullText.data(), bytes);
          GlobalUnlock(hMem);
          SetClipboardData(CF_UNICODETEXT, hMem);
        }
        CloseClipboard();
        s_notifyTime = GetTickCount64();
      }
    }

    FillRect(s_memDC, &rc, g_BgBrush);
    SetBkMode(s_memDC, TRANSPARENT);
    SetTextColor(s_memDC, RGB(200, 200, 200));
    HFONT oldFont = (HFONT)SelectObject(s_memDC, g_Font);

    auto btn = [&](int id, const wchar_t *txt, int x, int y, bool active,
                   bool enabled = true) {
      RECT r{x, y, x + S(140), y + S(30)};
      HBRUSH b =
          enabled ? (active ? g_BtnActive : g_BtnInactive) : g_BtnDisabled;
      FillRect(s_memDC, &r, b);
      if (!enabled)
        SetTextColor(s_memDC, RGB(80, 80, 80));
      DrawTextW(s_memDC, txt, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
      if (!enabled)
        SetTextColor(s_memDC, RGB(200, 200, 200));
    };

    bool run = g_App.running;
    btn(1, run ? L"STOP" : L"START", S(10), S(10), run);
    btn(2, L"Dynamic", S(160), S(10), g_App.mode == 2);
    btn(3, L"Steady", S(310), S(10), g_App.mode == 1);
    btn(4, L"Benchmark", S(460), S(10), g_App.mode == 0);
    btn(5, L"Close", S(610), S(10), false);

    int y2 = S(50);
    int sel = g_App.selectedWorkload.load();
#if defined(_M_ARM64) || defined(__aarch64__)
    bool has512 = false;
    bool hasAVX2 = false;
#else
    bool has512 = g_Cpu.hasAVX512F && !g_ForceNoAVX512;
    bool hasAVX2 = g_Cpu.hasAVX2 && !g_ForceNoAVX2;
#endif

    // Workload selection - MAX POWER variants + Realistic
    btn(10, L"Auto", S(10), y2, sel == WL_AUTO);
    btn(11, L"Scalar (AVX-512)", S(160), y2, sel == WL_AVX512, has512);
    btn(12, L"Scalar (AVX2)", S(310), y2, sel == WL_AVX2, hasAVX2);
    btn(13, L"Scalar (Synthetic)", S(460), y2, sel == WL_SCALAR);
    btn(14, L"Scalar (Realistic)", S(610), y2, sel == WL_SCALAR_SIM);

    // Second row - Checkbox for auto-stop and Verify Hash button
    int y3 = S(90);

    // Checkbox: Stop after 3 minutes
    {
      int cbX = S(10), cbY = y3, cbSize = S(16);
      RECT cbRect = {cbX, cbY, cbX + cbSize, cbY + cbSize};
      // Draw checkbox border
      FrameRect(s_memDC, &cbRect, (HBRUSH)GetStockObject(WHITE_BRUSH));
      // Draw checkmark if enabled
      if (g_App.autoStopBenchmark) {
        HPEN oldPen = (HPEN)SelectObject(s_memDC, GetStockObject(WHITE_PEN));
        MoveToEx(s_memDC, cbX + S(3), cbY + S(8), nullptr);
        LineTo(s_memDC, cbX + S(6), cbY + S(12));
        LineTo(s_memDC, cbX + S(13), cbY + S(4));
        SelectObject(s_memDC, oldPen);
      }
      // Label
      SetTextColor(s_memDC, RGB(200, 200, 200));
      RECT labelRect = {cbX + cbSize + S(6), cbY - S(2), S(280), cbY + S(20)};
      DrawTextW(s_memDC, L"Stop benchmark after 3 minutes", -1, &labelRect,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }

    // Note about workloads - positioned at bottom right
    {
      SetTextColor(s_memDC, RGB(120, 120, 120)); // Dimmed text
      RECT noteRect = {S(380), S(615), S(750), S(700)};
      DrawTextW(s_memDC,
                L"Note: AVX workloads have increased computational\n"
                L"complexities, hence Jobs/s is not an indicator for\n"
                L"actual AVX2/AVX-512 acceleration. Scalar (Synthetic)\n"
                L"on ARM actually uses NEON.",
                -1, &noteRect, DT_LEFT | DT_WORDBREAK);
      SetTextColor(s_memDC, RGB(200, 200, 200)); // Restore color
    }

    btn(20, L"Verify Hash", S(610), y3, false);

    std::wstring modeName =
        (g_App.mode == 2 ? L"Dynamic"
                         : (g_App.mode == 1 ? L"Steady" : L"Benchmark"));
    std::wstring activeISA = GetResolvedISAName(sel);

    std::wstring part1 =
        L"Shader Stress " + APP_VERSION + L"\nOS: Windows (" + GetArchName() +
        L")" + L"\nMode: " + modeName + L"\nActive ISA: " + activeISA +
        L"\nJobs Done: " + FmtNum(g_App.shaders) +
        L"\n\n--- Performance ---\nRate (Jobs/s): " +
        FmtNum(g_App.currentRate) + L"\nTime: " + FmtTime(g_App.elapsed);

    if (g_App.mode == 2) {
      part1 += L"\nPhase: " + std::to_wstring(g_App.currentPhase) + L" / 16";
      part1 += L"\nLoop: " + std::to_wstring(g_App.loops);
    } else if (g_App.mode == 0) {
      part1 += L"\n\n--- Benchmark Rounds (60s each) ---";
      part1 += L"\n1st Minute: " +
               (g_App.benchRates[0] > 0
                    ? FmtNum(g_App.benchRates[0])
                    : (g_App.elapsed < 60 && run ? L"Running..." : L"-"));
      part1 += L"\n2nd Minute: " +
               (g_App.benchRates[1] > 0
                    ? FmtNum(g_App.benchRates[1])
                    : (g_App.elapsed >= 60 && g_App.elapsed < 120 && run
                           ? L"Running..."
                           : L"-"));
      part1 += L"\n3rd Minute: " +
               (g_App.benchRates[2] > 0
                    ? FmtNum(g_App.benchRates[2])
                    : (g_App.elapsed >= 120 && g_App.elapsed < 180 && run
                           ? L"Running..."
                           : L"-"));
      // Hash is displayed on the right side, not here
      if (g_App.benchComplete && g_App.benchWinner != -1) {
        part1 +=
            L"\n\nWINNER: Interval " + std::to_wstring(g_App.benchWinner + 1);
        part1 += L"\n(Results written to ShaderStress.log)";
      }
    }

    std::wstring partError = L"Errors: " + FmtNum(g_App.errors);
    std::wstring part3 = L"\n\n--- Stress Status ---";
    part3 += L"\nWorker Threads: " +
             FmtNum(g_App.activeCompilers + g_App.activeDecomp);
    part3 += L"\n  > Sim Compilers: " + FmtNum(g_App.activeCompilers);
    part3 += L"\n  > Decompressors: " + FmtNum(g_App.activeDecomp);
    part3 +=
        L"\nRAM Thread: " + std::wstring(g_App.ramActive ? L"ACTIVE" : L"Idle");
    part3 += L"\nI/O Threads: " +
             std::wstring(g_App.ioActive ? L"ACTIVE (1x)" : L"Idle");

    RECT tr{S(20), S(130), S(740), S(680)};
    DrawTextW(s_memDC, part1.c_str(), -1, &tr, DT_LEFT | DT_NOCLIP);
    RECT measure = tr;
    DrawTextW(s_memDC, part1.c_str(), -1, &measure, DT_LEFT | DT_CALCRECT);
    tr.top += (measure.bottom - measure.top);

    if (g_App.errors > 0)
      SetTextColor(s_memDC, RGB(255, 80, 80));
    else
      SetTextColor(s_memDC, RGB(80, 255, 80));
    DrawTextW(s_memDC, partError.c_str(), -1, &tr, DT_LEFT | DT_NOCLIP);
    measure = tr;
    DrawTextW(s_memDC, partError.c_str(), -1, &measure, DT_LEFT | DT_CALCRECT);
    tr.top += (measure.bottom - measure.top);

    SetTextColor(s_memDC, RGB(200, 200, 200));
    DrawTextW(s_memDC, part3.c_str(), -1, &tr, DT_LEFT | DT_NOCLIP);

    // Draw hash on right side (Moved left to avoid clipping)
    std::wstring paintHash = g_App.GetBenchHash();
    if (g_App.mode == 0 && !paintHash.empty()) {
      SetTextColor(s_memDC, RGB(120, 200, 255)); // Light blue for hash
      // Moved from 610 to 480 to give more room
      RECT hashRect = {S(480), S(125), S(750), S(200)};
      std::wstring hashLabel = L"Hash:\n" + paintHash;
      DrawTextW(s_memDC, hashLabel.c_str(), -1, &hashRect, DT_LEFT | DT_NOCLIP);
    }

    // Notification
    if (s_notifyTime > 0 && (GetTickCount64() - s_notifyTime < 5000)) {
      SetTextColor(s_memDC, RGB(80, 255, 80));
      RECT noteRect = {S(480), S(200), S(750), S(240)};
      DrawTextW(s_memDC, L"[Copied to Clipboard]", -1, &noteRect,
                DT_LEFT | DT_NOCLIP);
    }
    SetTextColor(s_memDC, RGB(200, 200, 200));

    BitBlt(ps.hdc, 0, 0, rc.right, rc.bottom, s_memDC, 0, 0, SRCCOPY);
    SelectObject(s_memDC, oldFont);
    EndPaint(h, &ps);
    return 0;
  }
  if (m == WM_LBUTTONDOWN) {
    int x = GET_X_LPARAM(l);
    int y = GET_Y_LPARAM(l);

    if (y > S(10) && y < S(40)) {
      bool clickedStart = (x > S(10) && x < S(150));
      int newMode = -1;
      if (x > S(160) && x < S(300))
        newMode = 2;
      else if (x > S(310) && x < S(450))
        newMode = 1;
      else if (x > S(460) && x < S(600))
        newMode = 0;
      else if (x > S(610) && x < S(750))
        PostMessage(h, WM_CLOSE, 0, 0);

      std::lock_guard<std::mutex> lock(g_StateMtx);

      auto StartWorkload = []() {
        // Apply the appropriate config for the selected workload
        ApplyWorkloadConfig(g_App.selectedWorkload.load());
        
        if (g_DynThread && g_DynThread->t.joinable())
          g_DynThread->t.join();
        if (g_App.mode == 2) {
          g_DynThread = std::make_unique<ThreadWrapper>();
          g_DynThread->t = std::thread(DynamicLoop);
        } else if (g_App.mode == 1) {
          int cpu = (int)g_Workers.size();
          int d = std::min(4, std::max(1, cpu / 2));
          int c = std::max(0, cpu - d);
          SetWork(c, d, true, true);
        } else {
          for (int i = 0; i < 3; ++i)
            g_App.benchRates[i] = 0;
          g_App.benchWinner = -1;
          g_App.benchComplete = false;
          SetWork((int)g_Workers.size(), 0, 0, 0);
        }
      };

      auto ResetState = []() {
        g_App.shaders = 0;
        g_App.elapsed = 0;
        g_App.loops = 0;
        g_App.currentPhase = 0;
        for (auto &w : g_Workers)
          w->localShaders = 0;
      };

      if (clickedStart) {
        g_App.running = !g_App.running;
        if (g_App.running) {
          g_App.Log(L"State changed: STARTED");
          g_App.resetTimer = true; // Only reset on START
          ResetState();
          StartWorkload();
        } else {
          g_App.Log(L"State changed: STOPPED");
          SetWork(0, 0, 0, 0);
          // Do NOT reset timer or benchmark data on stop
        }
      } else if (newMode != -1 && newMode != g_App.mode) {
        g_App.mode = newMode;
        std::wstring modeName =
            (newMode == 2 ? L"Dynamic"
                          : (newMode == 1 ? L"Steady" : L"Benchmark"));
        g_App.Log(L"Mode changed to: " + modeName);

        // When switching to Benchmark, default to Realistic if currently on Auto
        if (newMode == 0 && g_App.selectedWorkload == WL_AUTO) {
          g_App.selectedWorkload = WL_SCALAR_SIM;
          g_App.Log(L"Benchmark: Defaulting to " +
                    GetResolvedISAName(WL_SCALAR_SIM) + L" (can be changed)");
        } else if (newMode != 0 && g_App.selectedWorkload == WL_AUTO) {
          g_App.selectedWorkload = WL_AUTO;
          g_App.Log(L"Workload reset to: " + GetResolvedISAName(WL_AUTO));
        }

        if (g_App.running) {
          g_App.resetTimer = true; // Reset when changing mode while running
          ResetState();
          StartWorkload();
        }
      }
      InvalidateRect(h, nullptr, FALSE);
    }
    if (y > S(50) && y < S(80)) {
#if defined(_M_ARM64) || defined(__aarch64__)
      bool has512 = false;
      bool hasAVX2 = false;
#else
      bool has512 = g_Cpu.hasAVX512F && !g_ForceNoAVX512;
      bool hasAVX2 = g_Cpu.hasAVX2 && !g_ForceNoAVX2;
#endif

      int newSel = -1;
      if (x > S(10) && x < S(150))
        newSel = WL_AUTO;
      else if (x > S(160) && x < S(300) && has512)
        newSel = WL_AVX512;
      else if (x > S(310) && x < S(450) && hasAVX2)
        newSel = WL_AVX2;
      else if (x > S(460) && x < S(600))
        newSel = WL_SCALAR;
      else if (x > S(610) && x < S(750))
        newSel = WL_SCALAR_SIM;

      if (newSel != -1 && newSel != g_App.selectedWorkload) {
        g_ConfigVersion.fetch_add(1, std::memory_order_release);
        g_App.selectedWorkload = newSel;
        g_App.Log(L"User changed ISA to: " + GetResolvedISAName(newSel));
        if (g_App.running) {
          g_App.resetTimer = true;
        }
        InvalidateRect(h, nullptr, FALSE);
      }
    }
    // Second row - Checkbox and Verify Hash button
    if (y > S(90) && y < S(120)) {
      // Checkbox click area (checkbox + label)
      if (x > S(10) && x < S(280)) {
        g_App.autoStopBenchmark = !g_App.autoStopBenchmark;
        InvalidateRect(h, nullptr, FALSE);
      }
      if (x > S(610) && x < S(750)) {
        ShowVerifyDialog(h);
      }
    }
  }
  if (m == WM_TIMER) {
    InvalidateRect(h, nullptr, FALSE);
    return 0;
  }
  return DefWindowProc(h, m, w, l);
}

// Custom dark dialog state
static HWND g_HashEditBox = nullptr;
static std::wstring g_HashResult;
static bool g_HashValid = false;
static HashResult g_DecodedHash = {};

LRESULT CALLBACK HashDialogProc(HWND hwnd, UINT msg, WPARAM wParam,
                                LPARAM lParam) {
  switch (msg) {
  case WM_CREATE: {
    // Enable dark mode titlebar (Windows 10 1809+ / Windows 11)
    BOOL useDarkMode = TRUE;
    DwmSetWindowAttribute(hwnd, 20, &useDarkMode, sizeof(useDarkMode));

    // Create Edit control for hash input
    g_HashEditBox = CreateWindowExW(
        0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        S(20), S(60), S(360), S(28), hwnd, (HMENU)101, GetModuleHandle(nullptr),
        nullptr);
    SendMessage(g_HashEditBox, WM_SETFONT, (WPARAM)g_Font, TRUE);

    // Create Verify button (owner-drawn)
    CreateWindowExW(0, L"BUTTON", L"Verify",
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(20), S(100), S(120),
                    S(30), hwnd, (HMENU)102, GetModuleHandle(nullptr), nullptr);

    // Create Close button (owner-drawn)
    CreateWindowExW(0, L"BUTTON", L"Close",
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, S(260), S(100),
                    S(120), S(30), hwnd, (HMENU)103, GetModuleHandle(nullptr),
                    nullptr);

    g_HashResult = L"Enter a hash and click Verify";
    return 0;
  }
  case WM_DRAWITEM: {
    LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
    if (dis->CtlType == ODT_BUTTON) {
      bool pressed = (dis->itemState & ODS_SELECTED) != 0;
      HBRUSH brush = pressed ? g_BtnActive : g_BtnInactive;
      FillRect(dis->hDC, &dis->rcItem, brush);

      SetBkMode(dis->hDC, TRANSPARENT);
      SetTextColor(dis->hDC, RGB(200, 200, 200));
      HFONT oldFont = (HFONT)SelectObject(dis->hDC, g_Font);

      wchar_t btnText[32];
      GetWindowTextW(dis->hwndItem, btnText, 32);
      DrawTextW(dis->hDC, btnText, -1, &dis->rcItem,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE);

      SelectObject(dis->hDC, oldFont);
      return TRUE;
    }
    break;
  }
  case WM_CTLCOLOREDIT:
  case WM_CTLCOLORSTATIC: {
    HDC hdc = (HDC)wParam;
    SetTextColor(hdc, RGB(200, 200, 200));
    SetBkColor(hdc, RGB(40, 40, 40));
    return (LRESULT)s_EditBrush;
  }
  case WM_CTLCOLORBTN: {
    return (LRESULT)g_BtnInactive;
  }
  case WM_ERASEBKGND: {
    HDC hdc = (HDC)wParam;
    RECT rc;
    GetClientRect(hwnd, &rc);
    FillRect(hdc, &rc, g_BgBrush);
    return 1;
  }
  case WM_PAINT: {
    PAINTSTRUCT ps;
    BeginPaint(hwnd, &ps);

    SetBkMode(ps.hdc, TRANSPARENT);
    SetTextColor(ps.hdc, RGB(200, 200, 200));
    HFONT oldFont = (HFONT)SelectObject(ps.hdc, g_Font);

    // Title
    RECT titleRect = {S(20), S(15), S(380), S(50)};
    DrawTextW(ps.hdc, L"Hash Verification", -1, &titleRect, DT_LEFT);

    // Input label
    RECT labelRect = {S(20), S(40), S(380), S(60)};
    DrawTextW(ps.hdc, L"Enter hash (format: SS3-XXXXXXXXXXXXXXXX):", -1, &labelRect,
              DT_LEFT);

    // Result area - extended to show all content
    RECT resultRect = {S(20), S(145), S(380), S(480)};
    if (g_HashValid) {
      SetTextColor(ps.hdc, RGB(80, 255, 80)); // Green for valid
    } else if (!g_HashResult.empty() &&
               g_HashResult.find(L"INVALID") != std::wstring::npos) {
      SetTextColor(ps.hdc, RGB(255, 80, 80)); // Red for invalid
    }
    DrawTextW(ps.hdc, g_HashResult.c_str(), -1, &resultRect,
              DT_LEFT | DT_WORDBREAK);

    SelectObject(ps.hdc, oldFont);
    EndPaint(hwnd, &ps);
    return 0;
  }
  case WM_COMMAND: {
    if (LOWORD(wParam) == 102) { // Verify button
      wchar_t hashBuf[64] = {0};
      GetWindowTextW(g_HashEditBox, hashBuf, 64);
      std::wstring hashInput = hashBuf;

      // Trim whitespace
      size_t start = hashInput.find_first_not_of(L" \t\r\n");
      size_t end = hashInput.find_last_not_of(L" \t\r\n");
      if (start != std::wstring::npos && end != std::wstring::npos) {
        hashInput = hashInput.substr(start, end - start + 1);
      }

      if (hashInput.empty()) {
        g_HashResult = L"Please enter a hash to verify.";
        g_HashValid = false;
      } else {
        g_DecodedHash = ValidateBenchmarkHash(hashInput);

        if (g_DecodedHash.valid) {
          g_HashValid = true;
          g_HashResult = L"Hash is VALID!\n\n";
          g_HashResult += L"Version: ShaderStress " +
                          std::to_wstring(g_DecodedHash.versionMajor) + L"." +
                          std::to_wstring(g_DecodedHash.versionMinor) + L"\n";
          g_HashResult += L"OS: " + GetOsName(g_DecodedHash.os) + L"\n";
          g_HashResult +=
              L"Arch: " + GetArchNameFromCode(g_DecodedHash.arch) + L"\n";
          g_HashResult +=
              L"CPU Hash: " + std::to_wstring(g_DecodedHash.cpuHash) + L"\n";
          g_HashResult += L"Algorithm: Base62 + FNV1a Checksum\n\n";

          g_HashResult += L"Rates:\n";
          g_HashResult +=
              L"R0: " + std::to_wstring(g_DecodedHash.r0) + L" Jobs/s\n";
          g_HashResult +=
              L"R1: " + std::to_wstring(g_DecodedHash.r1) + L" Jobs/s\n";
          g_HashResult +=
              L"R2: " + std::to_wstring(g_DecodedHash.r2) + L" Jobs/s\n";

          if (g_DecodedHash.versionMajor != APP_VERSION_MAJOR ||
              g_DecodedHash.versionMinor != APP_VERSION_MINOR) {
            g_HashResult += L"\n(Note: Hash is from a different version)\n";
          }
        } else {
          g_HashValid = false;
          g_HashResult = L"INVALID HASH\n\n";
          g_HashResult += L"\"" + hashInput + L"\"\n\n";
          g_HashResult += L"Possible reasons:\n";
          g_HashResult += L"- Hash is corrupted\n";
          g_HashResult += L"- Hash was modified";
        }
      }
      InvalidateRect(hwnd, nullptr, TRUE);
    }
    if (LOWORD(wParam) == 103) { // Close button
      DestroyWindow(hwnd);
    }
    return 0;
  }
  case WM_CLOSE:
    DestroyWindow(hwnd);
    return 0;
  case WM_DESTROY:
    g_HashEditBox = nullptr;
    g_HashResult.clear();
    return 0;
  }
  return DefWindowProc(hwnd, msg, wParam, lParam);
}

void ShowVerifyDialog(HWND parent) {
  // Register window class for dialog
  static bool registered = false;
  if (!registered) {
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = HashDialogProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"ShaderStressHashDialog";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = g_BgBrush;
    RegisterClassExW(&wc);
    registered = true;
  }

  // Get parent window position
  RECT parentRect;
  GetWindowRect(parent, &parentRect);
  int px = parentRect.left + (parentRect.right - parentRect.left - S(400)) / 2;
  int py = parentRect.top + (parentRect.bottom - parentRect.top - S(500)) / 2;

  // Create dialog window
  HWND dialog = CreateWindowExW(
      WS_EX_DLGMODALFRAME, L"ShaderStressHashDialog", L"Verify Hash",
      WS_POPUP | WS_VISIBLE | WS_CAPTION | WS_SYSMENU, px, py, S(400), S(500),
      parent, nullptr, GetModuleHandle(nullptr), nullptr);

  // Modal message loop
  EnableWindow(parent, FALSE);
  MSG msg;
  while (IsWindow(dialog) && GetMessage(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  EnableWindow(parent, TRUE);
  SetForegroundWindow(parent);
}

void PrintHelp() {
  AllocConsole();
  freopen("CONOUT$", "w", stdout);
  wprintf(L"ShaderStress v%ls\n\n", APP_VERSION.c_str());
  printf(
      "Options:\n  --repro <seed> <complexity>  : Run a specific crash "
      "reproduction case.\n  --max-duration <sec>         : Automatically stop "
      "after N seconds.\n  --no-avx512                  : Force AVX2/Scalar "
      "path.\n  --no-avx2                    : Force Scalar path.\n");
  getchar();
  ExitProcess(0);
}
