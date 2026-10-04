@echo off
rem MSVC 환경과 vcpkg 경로를 잡은 뒤 인자로 받은 명령을 실행한다.
rem 예: tools\win-dev.cmd cmake --workflow --preset win-release
setlocal
rem vcvars64.bat 이 VCPKG_ROOT 를 Visual Studio 내장 vcpkg 로 덮어쓰므로 먼저 저장해 둔다.
set "PA_VCPKG_ROOT=%VCPKG_ROOT%"
if not defined PA_VCPKG_ROOT set "PA_VCPKG_ROOT=C:\vcpkg"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
  echo Visual Studio not found 1>&2
  exit /b 10
)
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 11
set "VCPKG_ROOT=%PA_VCPKG_ROOT%"

rem 관리자 소유 vcpkg 디렉터리를 이 프로세스에서만 안전한 git 디렉터리로 지정한다.
set "GIT_CONFIG_COUNT=1"
set "GIT_CONFIG_KEY_0=safe.directory"
set "GIT_CONFIG_VALUE_0=%VCPKG_ROOT:\=/%"
set "PA_CACHE=%LOCALAPPDATA%\prompt-airlock"
set "VCPKG_DOWNLOADS=%PA_CACHE%\vcpkg-downloads"
if not exist "%VCPKG_DOWNLOADS%" mkdir "%VCPKG_DOWNLOADS%"
set "PA_VCPKG_INSTALL_OPTIONS=--x-buildtrees-root=%PA_CACHE%\vcpkg-buildtrees;--x-packages-root=%PA_CACHE%\vcpkg-packages"

%*
exit /b %ERRORLEVEL%
