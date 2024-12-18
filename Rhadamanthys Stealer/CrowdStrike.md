
# CrowdStrike Falcon Queries

#event_simpleName=/ProcessRollup/
| CommandLine=/cmd.exe/i AND CommandLine=/.cmd/ AND CommandLine=/move/
 
#event_simpleName=/ProcessRollup/
| FileName=/findstr\.exe/i
| CommandLine=/\/i OR CommandLine=/\/v
 
#event_simpleName=/ProcessRollup/
| FileName=/tasklist\.exe/i
| CommandLine=/\.bat$/i OR CommandLine=/\.cmd$/i
 
#event_simpleName=/ProcessRollup/
| CommandLine="cmd" AND CommandLine="[InternetShortcut]" AND CommandLine=">"
 
#event_simpleName=/ProcessRollup/
| CommandLine=/cmd/ AND CommandLine="md"
 
#event_simpleName=/ProcessRollup/
| CommandLine=/cmd/ AND CommandLine=/\/c/ AND CommandLine=/copy/ AND CommandLine=/\/b/
 
#event_simpleName=/(Synthetic)?ProcessRollup2/ AND event_platform=Win
| ((GrandParentBaseFileName=/^OpenWith\.exe$/i AND ParentBaseFileName=/^OOBE-Maintenance/i))
 
#event_simpleName=/(Synthetic)?ProcessRollup2/
GrandParentBaseFileName=/OpenWith.exe/i AND Parent=/.*/i AND OriginalFilename = /AutoIT/i
 
//NOTE: Due to limitations in Crowdstrike, the below query may need to be run in a shorter timeframe due to join limit
#event_simpleName=/(Synthetic)?ProcessRollup2/
| ParentBaseFileName=/WMPNSCFG/ AND CommandLine=/dllhost/
| join({#event_simpleName=/DnsRequest/ AND event_platform=Win
}, limit=200000, include=[LocalIP, DomainName], field=[ContextProcessId, ComputerName])
 
#event_simpleName=/FileWritten/ FileName=/Almost\.cmd|Internet\.pif|Innowave/
 
#event_simpleName=FileCreateInfo OR #event_simpleName=*FileWritten
| in(field="SHA256HashData", values=["a841624b9936a625f45cfffc446271be2191c3204bf7baa7bdf8890e6db691f3"])
 
#event_simpleName=NetworkConnectIP4
| in(field="RemoteIP", values=["144.76.133.166"])

