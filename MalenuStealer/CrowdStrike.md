#event_simpleName=/(Synthetic)?ProcessRollup2/ event_platform="Win" 
| FileName=/^taskkill\.exe$/i 
| CommandLine=/(msedge|chrome|brave|discord|slack)\.exe/i 
| bucket(5min, limit=70, field=[ComputerName], function=([count(CommandLine, distinct=false, as=CommandLines), collect([UserName, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine])])) 
| _bucket:=formatTime(format="%c", field="_bucket") 
| rename(_bucket, as="TimeFrameStart") 
| select([TimeFrameStart, ComputerName, CommandLines, UserName, GrandParentBaseFileName, ParentBaseFileName, FileName, CommandLine]) 
| CommandLines > 10 

#event_simpleName=ProcessRollup2  
CommandLine=/--remote-debugging-port/i CommandLine=/--remote-allow-origins/i 

#event_simpleName=/PeFileWritten/  
| text:contains(string=FileName, substring=ComputerName) 
| select([@timestamp, ComputerName, FileName, FilePath, ContextProcessId]) 

SHA256HashData=/8d1b6a215e194bda4130a11c9e5111341f6b97428d3c1606a6dda67602b62384|ac0f02d78b3864df71c6a2529d98da15dd421ea4bcf2d0f1773fc35c7a16caa8|923c26cd40e7e046f38ad5455a2becf5c9694ad371fc34d593f249adb5f2fb6c|940c1e6daaf12c293b55c56d02d06c237fa6cf6e30cb643c1a6a8ddc25210428|533958e064d091b0fa8f31e7fe254380b5449552ecf24c4c94bf7fb8ae1ce327|d5d6383b49f2156b2327e8aadefc7a5558697afd94ea3d52db2a34808eeede06"/i 

#event_simpleName=/DnsRequest/i 
| DomainName=/malenugame\.blogspot\.com|malenugames\.blogspot\.com|supremeserve\.discloud\.app/i