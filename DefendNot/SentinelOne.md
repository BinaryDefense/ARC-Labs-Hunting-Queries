# SentinelOne Queries for Hunting on Suspicious Activities

## AMSI Provider Modification 

```
RegistryKeyPath ContainsCIS "AMSI\Providers" 
```
 

## Windows Defender Registry Modification 
```
RegistryKeyPath RegExp "WMI\\AutoLogger\\(DefenderAuditLogger|DefenderApiLogger)"  
```

 
## DefendNot Antivirus Provider Registry Modification 
```
RegistryKeyPath ContainsCIS "Microsoft\Security Center\Provider\Av"  
```
 

## DefendNot File Hunt 
```
TgtFilePath EndsWithCIS "ctx.bin" 
```
 
## DefendNot  Scheduled Task Persistence 
```
ObjectType = "SCHEDULED_TASK" AND TaskName RegExp "defendnot|autorun|Loader" 
```
