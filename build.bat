@echo off
copy /Y winconfig.h config.h
cl /O2 /MD /DHAVE_CONFIG_H /DWIN32 /DFTPD_DECLARE_EXPORT /I"C:\Program Files\Microsoft SDK\Include" /I"C:\Program Files\Apache Group\Apache2\Include" ftp_core.c ftp_protocol.c
