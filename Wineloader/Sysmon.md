**Detect certutil.exe with specific command line arguments:**

\<QueryList\>

\<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational"\>

\<Select Path="Microsoft-Windows-Sysmon/Operational"\>

\*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=1)]] and

\*[EventData[Data[@Name='Image'] and (Data='C:\\\\Windows\\\\System32\\\\certutil.exe')]] and

\*[EventData[Data[@Name='CommandLine'] and contains(Data, 'certutil') and contains(Data, 'decode') and contains(Data, 'C:\\\\Windows\\\\Tasks\\\\')]]

\</Select\>

\</Query\>

\</QueryList\>

**Detect file events in C:\\Windows\\Tasks\\ folder with specific file extensions:**

\<QueryList\>

\<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational"\>

\<Select Path="Microsoft-Windows-Sysmon/Operational"\>

\*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=11)]] and

\*[EventData[Data[@Name='TargetFilename'] and (contains(Data, 'C:\\\\Windows\\\\Tasks\\\\')) and (ends-with(Data, '.dll') or ends-with(Data, '.exe'))]]

\</Select\>

\</Query\>

\</QueryList\>

**Detect schtasks.exe process with specific command line arguments:**

\<QueryList\>

\<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational"\>

\<Select Path="Microsoft-Windows-Sysmon/Operational"\>

\*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=1)]] and

\*[EventData[Data[@Name='Image'] and (Data='C:\\\\Windows\\\\System32\\\\schtasks.exe')]] and

\*[EventData[Data[@Name='CommandLine'] and contains(Data, 'sqlwriter.exe')]]

\</Select\>

\</Query\>

\</QueryList\>

**Detect registry events related to a specific registry key:**

\<QueryList\>

\<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational"\>

\<Select Path="Microsoft-Windows-Sysmon/Operational"\>

\*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=13)]] and

\*[EventData[Data[@Name='TargetObject'] and contains(Data, 'HKEY_CURRENT_USER\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\MS SQL Writer')]]

\</Select\>

\</Query\>

\</QueryList\>

**Detect network events initiated by mshta:**

\<QueryList\>

\<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational"\>

\<Select Path="Microsoft-Windows-Sysmon/Operational"\>

\*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=3)]] and

\*[EventData[Data[@Name='Image'] and (Data='C:\\\\Windows\\\\System32\\\\mshta.exe')]]

\</Select\>

\</Query\>

\</QueryList\>

**Detect file events initiated by mshta.exe:**

\<QueryList\>

\<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational"\>

\<Select Path="Microsoft-Windows-Sysmon/Operational"\>

\*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=11)]] and

\*[EventData[Data[@Name='Image'] and (Data='C:\\\\Windows\\\\System32\\\\mshta.exe')]]

\</Select\>

\</Query\>

\</QueryList\>

**Detect process events initiated by mshta.exe with specific command line arguments:**

\<QueryList\>

\<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational"\>

\<Select Path="Microsoft-Windows-Sysmon/Operational"\>

\*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=1)]] and

\*[EventData[Data[@Name='ParentImage'] and (Data='C:\\\\Windows\\\\System32\\\\mshta.exe')]] and

(\*[EventData[Data[@Name='CommandLine'] and (contains(Data, 'tar') and contains(Data, '-xf'))]] or

\*[EventData[Data[@Name='CommandLine'] and contains(Data, 'unrar')]] or

\*[EventData[Data[@Name='CommandLine'] and (contains(Data, '7z') and contains(Data, 'e'))]])

\</Select\>

\</Query\>

\</QueryList\>

**Detect image load events where sqlwriter.exe loaded vcruntime140.dll:**

\<QueryList\>

\<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational"\>

\<Select Path="Microsoft-Windows-Sysmon/Operational"\>

\*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=7)]] and

\*[EventData[Data[@Name='Image'] and (Data='C:\\\\Windows\\\\System32\\\\sqlwriter.exe')]] and

\*[EventData[Data[@Name='LoadedModuleName'] and (Data='C:\\\\Windows\\\\System32\\\\vcruntime140.dll')]]

\</Select\>

\</Query\>

\</QueryList\>

**Detect file events based on specific SHA256 hashes:**

\<QueryList\>

\<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational"\>

\<Select Path="Microsoft-Windows-Sysmon/Operational"\>

\*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=11)]] and

\*[EventData[Data[@Name='Hashes'] and

(contains(Data, 'SHA256=72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4') or

contains(Data, 'SHA256=ad43bbb21e2524a71bad5312a7b74af223090a8375f586d65ff239410bbd81a7') or

contains(Data, 'SHA256=3739b2eae11c8367b576869b68d502b97676fb68d18cc0045f661fbe354afcb9') or

contains(Data, 'SHA256=1c7593078f69f642b3442dc558cddff4347334ed7c96cd096367afd08dca67bc') or

contains(Data, 'SHA256=e477f52a5f67830d81cf417434991fe088bfec21984514a5ee22c1bcffe1f2bc') or

contains(Data, 'SHA256=f61cee951b7024fca048175ca0606bfd550437f5ba2824c50d10bef8fb54ca45') or

contains(Data, 'SHA256=c1223aa67a72e6c4a9a61bf3733b68bfbe08add41b73ad133a7c640ba265a19e') or

contains(Data, 'SHA256=b014cdff3ac877bdd329ca0c02bdd604817e7af36ad82f912132c50355af0920') or

contains(Data, 'SHA256=7600d4bb4e159b38408cb4f3a4fa19a5526eec0051c8c508ef1045f75b0f6083'))]

\</Select\>

\</Query\>

\</QueryList\>

**Detect network events based on specific URLs:**

\<QueryList\>

\<Query Id="0" Path="Microsoft-Windows-Sysmon/Operational"\>

\<Select Path="Microsoft-Windows-Sysmon/Operational"\>

\*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=3)]] and

\*[EventData[Data[@Name='DestinationHostname'] and

(Data='castechtools.com' or Data='seeceafcleaners.co.uk' or Data='passatempobasico.com.br' or Data='waterforvoiceless.org')]]

\</Select\>

\</Query\>

\</QueryList\>
