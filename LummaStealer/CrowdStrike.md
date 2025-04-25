#event_simpleName=/Process/i  
| FileName=/mshta\.exe/i CommandLine=/http/i  

#event_simpleName=/NetworkConnectIP(4|6)/ event_platform="Win"  
| RemoteAddressIP4=*  
| rename(ContextProcessId, as="TargetProcessId")  
| select([@timestamp, ComputerName, UserName, LocalAddressIP4, LocalAddressIP6,  
RemoteAddressIP4, RemoteAddressIP6, LocalPort, RemotePort, TargetProcessId])  
| join({#event_simpleName=/(Synthetic)?ProcessRollup2/  
| FileName=/mshta\.exe/i  
}, limit=200000, include=[UserName, FileName, SHA256HashData, ParentBaseFileName,  
GrandParentBaseFileName, CommandLine], field=[TargetProcessId, ComputerName])  

#event_simpleName=/((Synthetic)?ProcessRollup2|ScriptControl)/ event_platform="Win"  
| CommandLine = /Net.Webclient/i  
| CommandLine = /hidden/i  
| CommandLine = /bypass/i  
| select([@timestamp, ComputerName, aip, TargetProcessId, FileName, ParentBaseFileName,  
GrandParentBaseFileName, CommandLine, FilePath])  