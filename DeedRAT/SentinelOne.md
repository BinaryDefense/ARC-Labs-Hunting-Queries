TgtProcName In AnyCase ("MicRun.exe")
 
TgtFilePath StartsWithCIS "C:\ProgramData\Micro\Defaults"
 
RegistryKeyPath EndsWithCIS "CurrentVersion\Run\MicRun" AND RegistryValue RegExp "-[A-Z]{0,7}_[A-Z]{0,7}_[A-Z]{0,8}"
 
TgtProcCmdLine ContainsCIS "sc" AND TgtProcCmdLine ContainsCIS "create" AND TgtProcCmdLine ContainsCIS "MicRun"
 
Sha256 In AnyCase ("52f489d47618db8dfb503d6da98cbd76d08b063cc7ce0aac02b03601b6cae6a1" , "99a0b424bb3a6bbf60e972fd82c514fd971a948f9cedf3b9dc6b033117ecb106" , "e356dbd3bd62c19fa3ff8943fc73a4fab01a6446f989318b7da4abf48d565af2" , "2d9107edad9f674f6ca1707d56619a355227a661163f18b5794326d4f81a2803")
 
TgtFilePath In Contains Anycase ("SBAMRES.DLL" , "MicRun.exe" , "SBAMRES.DLL.CC")
 
Url ContainsCIS "luckybear669.kozow.com"