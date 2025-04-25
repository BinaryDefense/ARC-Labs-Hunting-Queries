EventType = "Process Creation" AND TgtProcName ContainsCIS "mshta.exe" AND TgtProcCmdLine ContainsCIS "http"  

EventType = "IP Connect" AND SrcProcName ContainsCIS "mshta.exe"  

EventType = "IP Connect" AND SrcProcName ContainsCIS "Powershell" AND SrcProcCmdLine ContainsCIS "hidden" AND SrcProcCmdLine ContainsCIS "bypass" AND SrcProcCmdLine ContainsCIS "Net.WebClient"  