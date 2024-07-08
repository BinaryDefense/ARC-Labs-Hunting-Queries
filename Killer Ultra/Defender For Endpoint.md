# Windows Defender for Endpoint Queries for Detecting Suspicious Activities

## Query to Detect Clearing Event Logs

kql
DeviceProcessEvents
| where ProcessCommandLine contains "cmd.exe /c \"for /F \"tokens=* \" %i in ('wevtutil.exe el') DO wevtutil.exe cl %i\""

## Query to Detect Execution of Suspicious Executables from c:\temp

DeviceProcessEvents
| where FileName in ("mimi.exe", "program.exe", "Maintainence.exe")
| where FolderPath startswith "C:\\temp" or FolderPath startswith "C:\\ProgramData\\Microsoft\\SystemMaintainence"

## Query to Detect File Writes of Specific Files

DeviceFileEvents
| where (FileName in ("mimi.exe", "program.exe") and FolderPath startswith "C:\\temp") or 
       (FileName contains "trevor") or 
       (SHA256 == "6F55C148BB27C14408CF0F16F344ABCD63539174AC855E510A42D78CFAEC451C")
	   
## Query to Detect Creation of Scheduled Tasks	   
	   DeviceEvents
| where ActionType == "TaskCreated"
| where (FolderPath == "C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe" and InitiatingProcessFileName == "Microsoft Security") or 
       (FolderPath == "C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe" and InitiatingProcessFileName == "Microsoft Maintenance")
	   
## Detect Service

DeviceEvents
| where ActionType == "ServiceCreated"
| where ServiceName == "StopGuard"

## Query to Detect Registry Modifications

DeviceRegistryEvents
| where RegistryKey == "HKLM\\System\\ControlSet001\\Services\\StopGuard"