@echo off
copy /Y winconfig.h config.h
mkdir Release
cd Release
echo /MD /W3 /Zi /O2 /DNDEBUG /D_WINDOWS /DWIN32 > RESP.txt
echo /Fd"mod_ftpd" /FD >> RESP.txt
echo /DHAVE_CONFIG_H /DFTPD_DECLARE_EXPORT  >> RESP.txt
echo /I.. >> RESP.txt
echo /I"C:\Program Files\Microsoft SDK\Include" >> RESP.txt
echo /I"C:\Program Files\Apache Group\Apache2\Include" >> RESP.txt
cl @RESP.txt /c ..\ftp_core.c ..\ftp_protocol.c ..\win32.c

echo /MACHINE:I386 /SUBSYSTEM:windows > RESP.txt
echo /OUT:mod_ftpd.so /DLL /OPT:REF /DEBUG >> RESP.txt
echo /LIBPATH:"C:\Program Files\Apache Group\Apache2\lib" >> RESP.txt
echo libapr.lib libaprutil.lib libhttpd.lib >> RESP.txt
link @RESP.txt ftp_core.obj ftp_protocol.obj win32.obj
cd ..
