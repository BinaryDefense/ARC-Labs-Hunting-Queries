DeviceProcessEvents  
\| where ProcessCommandLine has_all ("cmd.exe", ".cmd", "move")

DeviceProcessEvents  
\|where FileName has "findstr.exe" and (ProcessCommandLine has_any (@"/I", @"/V"))

DeviceProcessEvents  
\| where FileName has ("tasklist.exe")  
\| where InitiatingProcessCommandLine has_any (".bat",".cmd")  
\| project-reorder ProcessCommandLine,InitiatingProcessCommandLine,InitiatingProcessFileName,InitiatingProcessParentFileName

DeviceProcessEvents  
\|where ProcessCommandLine has_all ("cmd" , "[InternetShortcut]" , "\>")

DeviceProcessEvents  
\|where ProcessCommandLine has_all ("cmd", "md")

DeviceProcessEvents  
\|where ProcessCommandLine has_all ("cmd" , "/c" , "copy", "/b")

DeviceProcessEvents  
\|where InitiatingProcessParentFileName has "OpenWith.exe" and ProcessVersionInfoOriginalFileName contains "AutoIt"

DeviceEvents  
\|where InitiatingProcessFileName has "OOBE-Maintenance" and InitiatingProcessParentFileName has "OpenWith.exe"

DeviceNetworkEvents  
\|where InitiatingProcessCommandLine has "dllhost" and InitiatingProcessParentFileName has "WMPNSCFG"

DeviceFileEvents  
\|where FileName has_any ("Almost.cmd", "Internet.pif", "InnoWave") or SHA256 has "a841624b9936a625f45cfffc446271be2191c3204bf7baa7bdf8890e6db691f3"

DeviceNetworkEvents  
\|where RemoteIP has "144.76.133.166"
