
# CrowdStrike Falcon Queries

## 1. cmd.exe with .cmd
```fql
event_simpleName="ProcessRollup2" AND CommandLine:*cmd.exe* AND CommandLine:*.cmd*
```

## 2. findstr.exe with switches
```fql
event_simpleName="ProcessRollup2" AND FileName="findstr.exe" AND (CommandLine:*/I* OR CommandLine:*/V*)
```

## 3. tasklist.exe
```fql
event_simpleName="ProcessRollup2" AND FileName="tasklist.exe"
```

## 4. cmd with [InternetShortcut] and redirection (>)
```fql
event_simpleName="ProcessRollup2" AND CommandLine:*cmd* AND CommandLine:*[InternetShortcut]* AND CommandLine:* > *
```

## 5. cmd with md command
```fql
event_simpleName="ProcessRollup2" AND CommandLine:*cmd* AND CommandLine:*md*
```

## 6. cmd with /c copy /b
```fql
event_simpleName="ProcessRollup2" AND CommandLine:*cmd* AND CommandLine:*/c* AND CommandLine:*copy* AND CommandLine:*/b*
```

## 7. OpenWith.exe initiating AutoIt
```fql
event_simpleName="ProcessRollup2" AND ParentFileName="OpenWith.exe" AND OriginalFileName:*AutoIt*
```

## 8. OOBE-Maintenance with OpenWith.exe
```fql
event_simpleName="ProcessRollup2" AND FileName="OOBE-Maintenance" AND ParentFileName="OpenWith.exe"
```

## 9. dllhost with WMPNSCFG
```fql
event_simpleName="NetworkConnect" AND CommandLine:*dllhost* AND ParentFileName="WMPNSCFG"
```

## 10. Almost.cmd, Internet.pif, InnoWave, or specific SHA256
```fql
event_simpleName="FileWrite" AND (FileName IN ["Almost.cmd", "Internet.pif", "InnoWave"] OR SHA256="a841624b9936a625f45cfffc446271be2191c3204bf7baa7bdf8890e6db691f3")
```

## 11. Network connection to specific IP
```fql
event_simpleName="NetworkConnect" AND RemoteAddress="144.76.133.166"
```
