DeviceProcessEvents  
| where FileName has "mshta.exe"  
| where ProcessCommandLine contains "http"  

DeviceNetworkEvents    
| where InitiatingProcessFileName has "mshta"  

DeviceNetworkEvents  
|where InitiatingProcessFileName contains "powershell" and InitiatingProcessCommandLine has_all ("hidden" , "bypass" , "Net.WebClient")  

DeviceEvents   
| where InitiatingProcessFileName =~ "explorer.exe"  
| where ActionType =~ "GetClipboardData"  
| extend ClipBoardBinTime = bin(TimeGenerated,30m)  
| join (DeviceProcessEvents  
| where FileName =~ "mshta.exe"  
|extend mshtaBinTime = bin(TimeGenerated,30m) )on DeviceName, $left.ClipBoardBinTime==$right.mshtaBinTime   