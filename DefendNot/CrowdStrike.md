# CrowdStrike Queries for Hunting on Suspicious Activities

## AMSI Provider Modification 
```
#event_simpleName=/reg|asep/i RegObjectName=/AMSI\\Providers\\/i   
```
## Windows Defender Registry Modification 
```
#event_simpleName=/process/i event_platform="Win"
| rename(FileName, as="ContextFileName")
| rename(CommandLine, as="ResponsibleCommandLine")
| join({#event_simpleName=/reg|asep/i RegObjectName=/WMI\AutoLogger\(DefenderAuditLogger|DefenderApiLogger)/i
| rename(ContextProcessId, as="TargetProcessId")   }, include=[RegObjectName, RegStringValue], field=[TargetProcessId, ComputerName])
| ContextFileName=*
| select([@timestamp, ComputerName, ContextFileName, ResponsibleCommandLine, RegObjectName, ContextProcessId]) 
```
## DefendNot Antivirus Provider Registry Modification  
```
#event_simpleName=/asep|reg/i RegObjectName=/Microsoft\\Security Center\\Provider\\Av/i 
```
## DefendNot File Hunt  
```
#event_simpleName=/write|create/i FileName=/ctx.bin/i 
```
## DefendNot Scheduled Task Creation 
```
#event_simpleName=/ScheduledTask/i TaskName=/defendnot|autorun|Loader/i
```
