
# Splunk Sysmon Queries

## 1. Processes with 'cmd.exe' and '.cmd' in the command line
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1
| search CommandLine="*cmd.exe*" CommandLine="*.cmd*"
```

---

## 2. 'findstr.exe' executions with '/I' or '/V' switches
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1
| search Image="*findstr.exe*" (CommandLine="*/I*" OR CommandLine="*/V*")
```

---

## 3. Executions of 'tasklist.exe'
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1
| search Image="*tasklist.exe*"
```

---

## 4. 'cmd' executions with '[InternetShortcut]' and redirection ('>')
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1
| search CommandLine="*cmd*" CommandLine="*[InternetShortcut]*" CommandLine="*>*"
```

---

## 5. 'cmd' executions with 'md' command
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1
| search CommandLine="*cmd*" CommandLine="*md*"
```

---

## 6. 'cmd' executions with '/c copy /b'
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1
| search CommandLine="*cmd*" CommandLine="*/c*" CommandLine="*copy*" CommandLine="*/b*"
```

---

## 7. 'OpenWith.exe' initiating processes with 'AutoIt' in original file name
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1
| search ParentImage="*OpenWith.exe*" OriginalFileName="*AutoIt*"
```

---

## 8. 'OOBE-Maintenance' initiated by 'OpenWith.exe'
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1
| search Image="*OOBE-Maintenance*" ParentImage="*OpenWith.exe*"
```

---

## 9. 'dllhost' initiated by 'WMPNSCFG'
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1
| search CommandLine="*dllhost*" ParentImage="*WMPNSCFG*"
```

---

## 10. File events for specific file names or SHA256 hash
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=11
| search TargetFilename IN ("Almost.cmd", "Internet.pif", "InnoWave") OR Hashes="SHA256=a841624b9936a625f45cfffc446271be2191c3204bf7baa7bdf8890e6db691f3"
```

---

## 11. Network connection to specific IP address
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=3
| search DestinationIp="144.76.133.166"
```
