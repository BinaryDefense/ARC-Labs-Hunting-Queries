#event_simpleName=/(ImageHash|ClassifiedModuleLoad|UnsignedModuleLoad)/
| FileName=/MicRun\.exe/i

#event_simpleName=/File|Written/i
| FilePath=/ProgramData\\Micro\\Defaults/i

#event_simpleName=/Reg|Asep/i 
| RegObjectName=/\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/i
| RegValueName=/MicRun/i
| RegStringValue=/-[A-Z]{0,7}_[A-Z]{0,7}_[A-Z]{0,8}/i

#event_simpleName=/process/i 
| CommandLine=/sc/i CommandLine=/create/i CommandLine=/MicRun/i

SHA256HashData=/52f489d47618db8dfb503d6da98cbd76d08b063cc7ce0aac02b03601b6cae6a1|99a0b424bb3a6bbf60e972fd82c514fd971a948f9cedf3b9dc6b033117ecb106|e356dbd3bd62c19fa3ff8943fc73a4fab01a6446f989318b7da4abf48d565af2|2d9107edad9f674f6ca1707d56619a355227a661163f18b5794326d4f81a2803/i 

#event_simpleName=/process/i 
| FileName=/SBAMRES\.dll|MicRun\.exe|SBAMRES\.dll\.cc/i

#event_simpleName=/File|Written/i
| FileName=/SBAMRES\.dll|MicRun\.exe|SBAMRES\.dll\.cc/i

#event_simpleName=/DnsRequest/i
| DomainName=/luckybear669\.kozow\.com/i