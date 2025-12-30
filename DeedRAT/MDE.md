DeviceImageLoadEvents 
|where FileName has "MicRun.exe" 

DeviceFileEvents 
|where FolderPath contains @"C:\ProgramData\Micro\Defaults" 
  
DeviceRegistryEvents 
|where ActionType == "RegistryValueSet" and (RegistryKey has (@"CurrentVersion\Run")) 
|where RegistryValueName has "MicRun" 
|where RegistryValueData matches regex @"-[A-Z]{0,7}_[A-Z]{0,7}_[A-Z]{0,8}" 

DeviceProcessEvents 
|where ProcessCommandLine has_all ("sc", "create" , "MicRun") 

DeviceProcessEvents 
|where SHA256 has_any ("52f489d47618db8dfb503d6da98cbd76d08b063cc7ce0aac02b03601b6cae6a1" , "99a0b424bb3a6bbf60e972fd82c514fd971a948f9cedf3b9dc6b033117ecb106" , "e356dbd3bd62c19fa3ff8943fc73a4fab01a6446f989318b7da4abf48d565af2" , "2d9107edad9f674f6ca1707d56619a355227a661163f18b5794326d4f81a2803") 

DeviceFileEvents 
|where SHA256 has_any ("52f489d47618db8dfb503d6da98cbd76d08b063cc7ce0aac02b03601b6cae6a1" , "99a0b424bb3a6bbf60e972fd82c514fd971a948f9cedf3b9dc6b033117ecb106" , "e356dbd3bd62c19fa3ff8943fc73a4fab01a6446f989318b7da4abf48d565af2" , "2d9107edad9f674f6ca1707d56619a355227a661163f18b5794326d4f81a2803") 

DeviceProcessEvents 
|where FileName has_any ("SBAMRES.DLL" , "MicRun.exe" , "SBAMRES.DLL.CC") 

DeviceFileEvents 
|where FileName has_any  ("SBAMRES.DLL" , "MicRun.exe" , "SBAMRES.DLL.CC") 

DeviceNetworkEvents 
|where RemoteUrl has "luckybear669.kozow.com" 