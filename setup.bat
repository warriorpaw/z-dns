@echo off
echo set WshShell = createobject("wscript.shell") >>z-dns.vbs
echo WshShell.CurrentDirectory = "%~dp0" >>z-dns.vbs
echo WshShell.run "%~dp0z.DNS.py",vbhide >>z-dns.vbs
echo WshShell.run "WMIC PATH Win32_Process WHERE Name='python.exe' call SetPriority 32768",vbhide >>z-dns.vbs
echo wscript.quit >>z-dns.vbs


echo "请把生成的z-dns.vbs复制到 开始菜单 > 启动 位置 , 即可开机后台自启动"
echo 如果z.DNS所在文件夹被移动了，VBS脚本需要重新生成的
pause