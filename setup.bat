@echo off
echo set WshShell = createobject("wscript.shell") >>z-dns.vbs
echo WshShell.CurrentDirectory = "%~dp0" >>z-dns.vbs
echo WshShell.run "%~dp0z.DNS.py",vbhide >>z-dns.vbs
echo WshShell.run "WMIC PATH Win32_Process WHERE Name='python.exe' call SetPriority 32768",vbhide >>z-dns.vbs
echo wscript.quit >>z-dns.vbs


echo "������ɵ�z-dns.vbs���Ƶ� ��ʼ�˵� > ���� λ�� , ���ɿ�����̨������"
echo ���z.DNS�����ļ��б��ƶ��ˣ�VBS�ű���Ҫ�������ɵ�
pause