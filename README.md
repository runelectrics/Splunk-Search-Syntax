![Splunk Hunt Searches](splunk.jpeg)

# [Splunk Hunting](https://github.com/runelectrics/Splunk-Search-Syntax) 


**A collection of searches using Splunk for threat hunting**

Your [contributions](contributing.md) are always welcome !

## General Searches

Lookup Search
```
| lookup open_nameservers ip
| stats count by ip
```

Search Index for earliest logs

```
index=index_name  earliest=0 
```

### Windows Log Searches
Monitor For anomalous administrator processes
```
index=windows LogName=Security EventCode=4688 NOT (Account_Name=*$) (arp.exe OR at.exe OR bcdedit.exe OR bcp.exe OR chcp.exe OR cmd.exe OR cscript.exe OR csvde OR dsquery.exe OR ipconfig.exe OR mimikatz.exe OR nbtstat.exe OR nc.exe OR netcat.exe OR netstat.exe OR nmap OR nslookup.exe OR netsh OR OSQL.exe OR ping.exe OR powershell.exe OR powercat.ps1 OR psexec.exe OR psexecsvc.exe OR psLoggedOn.exe OR procdump.exe OR qprocess.exe OR query.exe OR rar.exe OR reg.exe OR route.exe OR runas.exe OR rundll32 OR schtasks.exe OR sethc.exe OR sqlcmd.exe OR sc.exe OR ssh.exe OR sysprep.exe OR systeminfo.exe OR system32\\net.exe OR reg.exe OR tasklist.exe OR tracert.exe OR vssadmin.exe OR whoami.exe OR winrar.exe OR wscript.exe OR "winrm.*" OR "winrs.*" OR wmic.exe OR wsmprovhost.exe OR wusa.exe)
| eval Message=split(Message,".") 
| eval Short_Message=mvindex(Message,0) 
| table _time, host, Account_Name, Process_Name, Process_ID, Process_Command_Line, New_Process_Name, New_Process_ID, Creator_Process_ID, Short_Message
```

Monitor PowerShell Bypass attempts 
```
index=<windowsindex> EventCode=4688 (powershell* AND (–ExecutionPolicyOR –Exp))OR (powershell* AND bypass) OR (powershell* AND (-noprofileOR -nop)) 
| eval Message=split(Message,".") 
| eval Short_Message=mvindex(Message,0) 
| table _time, host, Account_Name, Process_Name, Process_ID, Process_Command_Line, New_Process_Name, New_Process_ID, Creator_Process_ID, Short_Message
```

Looking for new process created
```
sourcetype="wineventlog:security"EventCode=4688
| stats count, values(Creator_Process_Name) as Creator_Process_Name by New_Process_Name
| table New_Process_Name, count, Creator_Process_Name
| sort count
```

### Proxy/Web Log Searches
Extract domain/uri/parameter from url string
```
| rex field=url "(?<domain>^\w+:\/\/[^\/]+\/)(?<uri>.+)(\?(?<parameter>.+))$"
```

### Misc.
Delimiter by semicolon
```
| makemv delim=";"
```

Geolocate by IP address
```
| iplocation ipaddress
| table Country City
```

Remove the object name from a datamodel search
```
| `drop_dm_object_name("Web")`
```
## References

[Hunting with Splunk: The Basics](https://www.splunk.com/blog/2017/07/06/hunting-with-splunk-the-basics.html)
[Windows MITRE Logging Cheat Sheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5b8f091c0ebbe8644d3a886c/1536100639356/Windows+ATT%26CK_Logging+Cheat+Sheet_ver_Sept_2018.pdf)
[Windows Splunk Logging Cheat Sheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5c795d0beef1a18fb703e450/1551457549199/Windows+Splunk+Logging+Cheat+Sheet+v2.21.pdf)
