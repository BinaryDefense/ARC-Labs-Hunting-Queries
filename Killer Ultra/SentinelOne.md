
# SentinelOne Deep Visibility Queries for Detecting Suspicious Activities

## Query to Detect Clearing Event Logs

```sql
query EventType=Process AND 
    CmdLine="cmd.exe /c \"for /F \"tokens=* \" %i in ('wevtutil.exe el') DO wevtutil.exe cl %i\""
```

## Query to Detect Execution of Suspicious Executables from c:\temp

```sql
query EventType=Process AND 
    (FilePath="C:\\temp\\mimi.exe" OR FilePath="C:\\temp\\program.exe" OR FilePath="C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe")
```

## Query to Detect File Writes of Specific Files

```sql
query EventType=File AND 
    (FilePath="C:\\temp\\mimi.exe" OR FilePath="C:\\temp\\program.exe" OR FilePath="C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe" OR 
     FilePath CONTAINS "trevor" OR 
     SHA256="6F55C148BB27C14408CF0F16F344ABCD63539174AC855E510A42D78CFAEC451C")
```

## Query to Detect Creation of Scheduled Tasks

```sql
query EventType=TaskCreated AND 
    (TaskName="Microsoft Security" AND FilePath="C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe") OR 
    (TaskName="Microsoft Maintenance" AND FilePath="C:\\ProgramData\\Microsoft\\SystemMaintainence\\Maintainence.exe")
```

## Query to Detect Service Creation Events

```sql
query EventType=Service AND 
    ServiceName="StopGuard"
```

## Query to Detect Registry Modifications

```sql
query EventType=Registry AND 
    RegistryKey="HKLM\\System\\ControlSet001\\Services\\StopGuard"
```


