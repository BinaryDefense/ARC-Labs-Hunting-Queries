# Defender for Endpoint Queries for Hunting on Suspicious Activities

## AMSI Provider Modification  
```kql
DeviceRegistryEvents  
| where RegistryKey contains "AMSI\\Providers\\"  
| project-reorder RegistryKey  
```
## File Name Hunt 
```kql
DeviceFileEvents 
| where FileName contains "ctx.bin" 
```
## DefendNot Registry Persistence 
```kql
DeviceRegistryEvents 
| where RegistryKey contains "taskcache" and RegistryKey contains "Defendnot" 
```
## DefendNot Scheduled Task Persistence 
```kql 
DeviceEvents 
| where ActionType contains "task" and (AdditionalFields contains "defendnot" or AdditionalFields contains “loader” or AdditionalFields contains “autorun”)
```
