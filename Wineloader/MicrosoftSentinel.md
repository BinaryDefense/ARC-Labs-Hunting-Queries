DeviceProcessEvents  
\| where FileName has "certutil.exe" and ProcessCommandLine has_all ("certutil" , "decode" , @"C:\\Windows\\Tasks\\")

DeviceFileEvents  
\| where FolderPath has (@"C:\\Windows\\Tasks\\") and FileName has_any (".dll" , ".exe")

DeviceProcessEvents  
\| where FileName has "schtasks.exe" and ProcessCommandLine has ("sqlwriter.exe")

DeviceRegistryEvents  
\| where RegistryKey has (@"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MS SQL Writer")

DeviceNetworkEvents  
\| where InitiatingProcessFileName has "mshta"

DeviceFileEvents

\| where InitiatingProcessFileName has "mshta.exe"

DeviceProcessEvents

\| where InitiatingProcessFileName =\~ "mshta.exe"  
\| where ProcessCommandLine has_all ("tar", "-xf") or ProcessCommandLine has "unrar" or ProcessCommandLine has_all ("7z" , "e")

DeviceImageLoadEvents  
\| where InitiatingProcessFileName has "sqlwriter.exe" and FileName has "vcruntime140.dll"

DeviceFileEvents  
\| where SHA256 in\~ ("72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4" , "ad43bbb21e2524a71bad5312a7b74af223090a8375f586d65ff239410bbd81a7" , "3739b2eae11c8367b576869b68d502b97676fb68d18cc0045f661fbe354afcb9" , "1c7593078f69f642b3442dc558cddff4347334ed7c96cd096367afd08dca67bc" , "e477f52a5f67830d81cf417434991fe088bfec21984514a5ee22c1bcffe1f2bc" , "f61cee951b7024fca048175ca0606bfd550437f5ba2824c50d10bef8fb54ca45" , "c1223aa67a72e6c4a9a61bf3733b68bfbe08add41b73ad133a7c640ba265a19e" , "b014cdff3ac877bdd329ca0c02bdd604817e7af36ad82f912132c50355af0920" , "7600d4bb4e159b38408cb4f3a4fa19a5526eec0051c8c508ef1045f75b0f6083")

DeviceNetworkEvents  
\| where RemoteUrl in\~ ("https://castechtools.com/api.php" , "https://seeceafcleaners.co.uk/cert.php" , "https://seeceafcleaners.co.uk/wine.php" , "https://passatempobasico.com.br/wine.php", "waterforvoiceless.org/util.php")
