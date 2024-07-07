
# CrowdStrike Falcon Queries for Detecting Suspicious Activities

## Query to Detect Clearing Event Logs

```sql
EventType=ProcessRollup2
| search CommandLine="cmd.exe /c \"for /F \"tokens=* \" %i in ('wevtutil.exe el') DO wevtutil.exe cl %i\""
| groupby [aid, EventTime]
```

## Query to Detect Execution of Suspicious Executables from c:\temp

```sql
EventType=ProcessRollup2
| search (ImageFileName="C:\\temp\\mimi.exe" OR ImageFileName="C:\\temp\\program.exe" OR ImageFileName="C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe")
| groupby [aid, EventTime, ImageFileName]
```

## Query to Detect File Writes of Specific Files

```sql
EventType=FileWrite
| search (FileName="C:\\temp\\mimi.exe" OR FileName="C:\\temp\\program.exe" OR FileName="C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe" OR FileName="*\\trevor" OR SHA256HashData="6F55C148BB27C14408CF0F16F344ABCD63539174AC855E510A42D78CFAEC451C")
| groupby [aid, EventTime, FileName]
```

## Query to Detect Creation of Scheduled Tasks

```sql
EventType=TaskCreated
| search (TaskName="Microsoft Security" AND TaskPath="C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe") OR (TaskName="Microsoft Maintenance" AND TaskPath="C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe")
| groupby [aid, EventTime, TaskName, TaskPath]
```

## Query to Detect Service Creation Events

```sql
EventType=ServiceCreate
| search ServiceName="StopGuard"
| groupby [aid, EventTime, ServiceName]
```

## Query to Detect Registry Modifications

```sql
EventType=RegistryModification
| search RegistryKeyName="HKLM\\System\\ControlSet001\\Services\\StopGuard"
| groupby [aid, EventTime, RegistryKeyName]
```

## Combined Detection Query

To create a comprehensive detection query that incorporates all these activities:

```sql
EventType=ProcessRollup2 OR EventType=FileWrite OR EventType=TaskCreated OR EventType=ServiceCreate OR EventType=RegistryModification
| search (
    (EventType=ProcessRollup2 AND (ImageFileName="C:\\temp\\mimi.exe" OR ImageFileName="C:\\temp\\program.exe" OR ImageFileName="C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe" OR CommandLine="cmd.exe /c \"for /F \"tokens=* \" %i in ('wevtutil.exe el') DO wevtutil.exe cl %i\"")) OR
    (EventType=FileWrite AND (FileName="C:\\temp\\mimi.exe" OR FileName="C:\\temp\\program.exe" OR FileName="C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe" OR FileName="*\\trevor" OR SHA256HashData="6F55C148BB27C14408CF0F16F344ABCD63539174AC855E510A42D78CFAEC451C")) OR
    (EventType=TaskCreated AND ((TaskName="Microsoft Security" AND TaskPath="C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe") OR (TaskName="Microsoft Maintenance" AND TaskPath="C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe"))) OR
    (EventType=ServiceCreate AND ServiceName="StopGuard") OR
    (EventType=RegistryModification AND RegistryKeyName="HKLM\\System\\ControlSet001\\Services\\StopGuard")
)
| groupby [aid, EventTime, EventType, ImageFileName, FileName, TaskName, TaskPath, ServiceName, RegistryKeyName]
```
