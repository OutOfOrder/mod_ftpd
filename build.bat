@echo off
copy /Y winconfig.h config.h
cl /O2 /MD /DHAVE_CONFIG_H /I"C:\Program Files\Apache Group\Apache2\Include" ftp_core.c
