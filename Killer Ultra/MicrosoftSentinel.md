
# Microsoft Sentinel Queries for Detecting Suspicious Activities

## Query to Detect Clearing Event Logs

```kql
SecurityEvent
| where EventID == 4688
| where ProcessCommandLine contains "cmd.exe /c \"for /F \"tokens=* \" %i in ('wevtutil.exe el') DO wevtutil.exe cl %i\""
```

## Query to Detect Execution of Suspicious Executables from c:\temp

```kql
SecurityEvent
| where EventID == 4688
| where ProcessName in ("C:\temp\mimi.exe", "C:\temp\program.exe", "C:\ProgramData\Microsoft\SystemMaintainence\Maintainence.exe")
```

## Query to Detect File Writes of Specific Files

```kql
FileEvents
| where (FileName == "C:\temp\mimi.exe" or FileName == "C:\temp\program.exe" or FileName == "C:\ProgramData\Microsoft\SystemMaintainence\Maintainence.exe" or FileName contains "trevor" or SHA256 == "6F55C148BB27C14408CF0F16F344ABCD63539174AC855E510A42D78CFAEC451C")
```

## Query to Detect Creation of Scheduled Tasks

```kql
SecurityEvent
| where EventID == 4698
| where (TaskName == "Microsoft Security" and ProcessName == "C:\ProgramData\Microsoft\SystemMaintainence\Maintainence.exe") or (TaskName == "Microsoft Maintenance" and ProcessName == "C:\ProgramData\Microsoft\SystemMaintainence\Maintainence.exe")
```

## Query to Detect Service Creation Events

```kql
SecurityEvent
| where EventID == 7045
| where ServiceName == "StopGuard"
```

## Query to Detect Registry Modifications

```kql
SecurityEvent
| where EventID == 4657
| where RegistryKey == "HKLM\System\ControlSet001\Services\StopGuard"
```

```
