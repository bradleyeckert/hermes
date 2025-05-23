@echo off
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
