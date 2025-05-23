@echo off
echo Only run this batch file if you want to overwrite files
echo with the latest from the local blake2s and xchacha repos.
echo.
set /P yesno=Do you want to continue? (y/n) 
if /i "%yesno%"=="y" goto continue
echo Exiting...
exit
:continue

if exist ..\..\blake2s (
  copy ..\..\blake2s\src\blake2s.c blake2s.c /y
  copy ..\..\blake2s\src\blake2s.h blake2s.h /y
) else (
  echo Missing blake2s folder, please clone the repo
)
if exist ..\..\xchacha (
  copy ..\..\xchacha\src\xchacha.c xchacha.c /y
  copy ..\..\xchacha\src\xchacha.h xchacha.h /y
) else (
  echo Missing xchacha folder, please clone the repo
)
