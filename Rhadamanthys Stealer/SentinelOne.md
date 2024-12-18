
# SentinelOne Deep Visibility Queries

EventType = "Process Creation" AND TgtProcCmdLine ContainsCIS "cmd.exe" AND TgtProcCmdLine ContainsCIS ".cmd" AND TgtProcCmdLine ContainsCIS "move"
 
EventType = "Process Creation" AND TgtProcName = "findstr.exe" AND TgtProcCmdLine In Contains Anycase ( "/I", "/V")
 
EventType = "Process Creation" AND TgtProcName = "tasklist.exe" AND SrcProcCmdLine In Contains Anycase (".bat", ".cmd")
 
EventType = "Process Creation" AND TgtProcCmdLine ContainsCIS "cmd" AND TgtProcCmdLine ContainsCIS "[InternetShortcut]" AND TgtProcCmdLine ContainsCIS ">"
 
EventType = "Process Creation" AND TgtProcCmdLine ContainsCIS "cmd" AND TgtProcCmdLine ContainsCIS "md"
 
EventType = "Process Creation" AND TgtProcCmdLine ContainsCIS "cmd" AND TgtProcCmdLine ContainsCIS "/c" AND TgtProcCmdLine ContainsCIS "copy" AND TgtProcCmdLine ContainsCIS "/b"
 
SrcProcParentName = "OpenWith.exe" AND SrcProcName ContainsCIS "OOBE-Maintenance"
 
SrcProcParentName ContainsCIS "WMPNSCFG" AND SrcProcCmdLine ContainsCIS "dllhost"
 
EventType In ( "File Creation", "File Modification", "File Deletion") AND (TgtFilePath In Contains Anycase ( "Almost.cmd", "Internet.pif", "InnoWave") OR Sha256 In AnyCase ( "a841624b9936a625f45cfffc446271be2191c3204bf7baa7bdf8890e6db691f3"))
 
IP = "144.76.133.166"
