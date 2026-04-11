@echo off
chcp 65001 >nul

echo =====================================
echo NETLAB BUILD AUTOMATICO
echo =====================================

echo.
echo Limpando builds antigos...
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
del NetLab.spec 2>nul

echo.
echo Instalando dependencias Python...
pip install -r requirements.txt

echo Instalando PyInstaller...
pip install pyinstaller

echo.
echo Gerando executavel...

pyinstaller ^
--clean ^
--noconfirm ^
--onedir ^
--windowed ^
--uac-admin ^
--collect-all PyQt6 ^
--collect-all scapy ^
--hidden-import scapy.arch.windows ^
--hidden-import scapy.layers.all ^
--icon=icon.ico ^
--add-data "recursos/estilos/tema_escuro.qss;recursos/estilos" ^
--name NetLab ^
main.py

echo.
echo =====================================
echo BUILD FINALIZADO
echo Executavel em: dist\NetLab
echo =====================================

pause