DeviceProcessEvents 
| where InitiatingProcessVersionInfoProductName =~ "electron" and InitiatingProcessFileName !~ "electron.exe" 

DeviceProcessEvents 
| where Timestamp > ago(30d) 
| where FileName has_any ("taskkill.exe") and ProcessCommandLine has_any ("msedge.exe", "chrome.exe", "firefox.exe", "discord.exe", "slack.exe", "brave.exe") 
| summarize count() by bin(Timestamp, 5m), DeviceId, DeviceName, ProcessCommandLine 
| summarize sum(count_) by Timestamp,DeviceId,DeviceName 
| where sum_count_ > 10 
| join (DeviceProcessEvents 
|where Timestamp > ago(30d) 
|where FileName has_any ("taskkill.exe") and ProcessCommandLine has_any ("msedge.exe", "chrome.exe", "firefox.exe", "discord.exe", "slack.exe", "brave.exe") 
| summarize CommandLines = make_set(ProcessCommandLine) by bin(Timestamp, 5m), DeviceId, DeviceName) on Timestamp,DeviceId,DeviceName 
| project Timestamp,CommandLines,sum_count_,DeviceName,DeviceId 

DeviceNetworkEvents 
| where ActionType =~ "ListeningConnectionCreated" and InitiatingProcessCommandLine has_all ("remote-debugging-port", "remote-allow-origins") and InitiatingProcessFileName in~ ("msedge.exe", "brave.exe", "chrome.exe") 

DeviceFileEvents 
| extend DeviceNameMinusDomain = extract(@"(.*)\..*\..*", 1, DeviceName) 
| where FileName contains DeviceName or FileName contains DeviceNameMinusDomain 

DeviceFileEvents 
| where SHA256 in~ ("8d1b6a215e194bda4130a11c9e5111341f6b97428d3c1606a6dda67602b62384", "ac0f02d78b3864df71c6a2529d98da15dd421ea4bcf2d0f1773fc35c7a16caa8", "923c26cd40e7e046f38ad5455a2becf5c9694ad371fc34d593f249adb5f2fb6c", "940c1e6daaf12c293b55c56d02d06c237fa6cf6e30cb643c1a6a8ddc25210428", "533958e064d091b0fa8f31e7fe254380b5449552ecf24c4c94bf7fb8ae1ce327", "d5d6383b49f2156b2327e8aadefc7a5558697afd94ea3d52db2a34808eeede06") 

DeviceNetworkEvents 
| where RemoteUrl has_any ("malenugame.blogspot.com", "malenugames.blogspot.com","supremeserve.discloud.app") 