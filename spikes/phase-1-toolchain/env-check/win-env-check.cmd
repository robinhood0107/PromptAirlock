@echo off
rem Windows clang-cl 환경 점검. 사용법: win-env-check.cmd <출력 디렉터리>
setlocal
set OUT=%~1
if "%OUT%"=="" set OUT=%~dp0out-win
if not exist "%OUT%" mkdir "%OUT%"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 10
set SRC=%~dp0expected_smoke.cpp
set FLAGS=/std:c++latest /EHsc /W4 /nologo

echo == clang-cl version
clang-cl --version
echo == debug
clang-cl %FLAGS% /Od /MDd /Zi "%SRC%" /Fe"%OUT%\smoke-debug.exe" /Fo"%OUT%\\" && "%OUT%\smoke-debug.exe"
echo exit=%ERRORLEVEL%
echo == release
clang-cl %FLAGS% /O2 /MD "%SRC%" /Fe"%OUT%\smoke-release.exe" /Fo"%OUT%\\" && "%OUT%\smoke-release.exe"
echo exit=%ERRORLEVEL%
echo == asan (release CRT)
clang-cl %FLAGS% /O1 /MD /Zi -fsanitize=address "%SRC%" /Fe"%OUT%\smoke-asan.exe" /Fo"%OUT%\\"
copy /y "C:\Program Files\LLVM\lib\clang\23\lib\windows\clang_rt.asan_dynamic-x86_64.dll" "%OUT%\" >nul
"%OUT%\smoke-asan.exe"
echo normal-exit=%ERRORLEVEL%
"%OUT%\smoke-asan.exe" --uaf 2> "%OUT%\asan-uaf.txt"
echo uaf-exit=%ERRORLEVEL%
findstr /c:"heap-use-after-free" "%OUT%\asan-uaf.txt" >nul && echo asan-detected=yes || echo asan-detected=no
echo == ubsan
clang-cl %FLAGS% /O1 /MD -fsanitize=undefined "%SRC%" /Fe"%OUT%\smoke-ubsan.exe" /Fo"%OUT%\\"
echo ubsan-build=%ERRORLEVEL%
if exist "%OUT%\smoke-ubsan.exe" (
  "%OUT%\smoke-ubsan.exe"
  echo normal-exit=%ERRORLEVEL%
  "%OUT%\smoke-ubsan.exe" --overflow x 2> "%OUT%\ubsan-overflow.txt"
  findstr /c:"signed integer overflow" "%OUT%\ubsan-overflow.txt" >nul && echo ubsan-detected=yes || echo ubsan-detected=no
)
endlocal
