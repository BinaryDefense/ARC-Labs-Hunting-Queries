# Sentinel Queries for Hunting on Suspicious Activities

## Windows Defender ACL Block Added 
```
datatable(target_service:dynamic) ["windefend", "mpssvc", "sense", "mdcoresvc", "wscsvc", "wdnissvc", "sysmon", "sysmon64"]
//SERVICES TO HUNT FOR
| mv-expand target_service
// Calculate SIDs
//convert UTF-8 to UTF-16
| extend uppercase_service = toupper(target_service)
| extend uppercase_service_utf16 = replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(replace_string(uppercase_service, " ", " \0"), "!", "!\0"), "\"", "\"\0"), "#", "#\0"), "$", "$\0"), "%", "%\0"), "&", "&\0"), "'", "'\0"), "(", "(\0"), ")", ")\0"), "*", "*\0"), "+", "+\0"), ",", ",\0"), "-", "-\0"), ".", ".\0"), "0", "0\0"), "1", "1\0"), "2", "2\0"), "3", "3\0"), "4", "4\0"), "5", "5\0"), "6", "6\0"), "7", "7\0"), "8", "8\0"), "9", "9\0"), ":", ":\0"), ";", ";\0"), "<", "<\0"), "=", "=\0"), ">", ">\0"), "?", "?\0"), "@", "@\0"), "A", "A\0"), "B", "B\0"), "C", "C\0"), "D", "D\0"), "E", "E\0"), "F", "F\0"), "G", "G\0"), "H", "H\0"), "I", "I\0"), "J", "J\0"), "K", "K\0"), "L", "L\0"), "M", "M\0"), "N", "N\0"), "O", "O\0"), "P", "P\0"), "Q", "Q\0"), "R", "R\0"), "S", "S\0"), "T", "T\0"), "U", "U\0"), "V", "V\0"), "W", "W\0"), "X", "X\0"), "Y", "Y\0"), "Z", "Z\0"), "[", "[\0"), "]", "]\0"), "^", "^\0"), "_", "_\0"), "`", "`\0"), "{", "{\0"), "|", "|\0"), "}", "}\0"), "~", "~\0")
// get hash
| extend uppercase_service_hash = hash_sha1(uppercase_service_utf16)
// convert hash to SID format
| extend hash1 = extract(@"(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)", 1, uppercase_service_hash)
| extend hash2 = extract(@"(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)", 2, uppercase_service_hash)
| extend hash3 = extract(@"(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)", 3, uppercase_service_hash)
| extend hash4 = extract(@"(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)", 4, uppercase_service_hash)
| extend hash5 = extract(@"(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)(\w\w\w\w\w\w\w\w)", 5, uppercase_service_hash)
| extend h1b1 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 1, hash1)
| extend h1b2 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 2, hash1)
| extend h1b3 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 3, hash1)
| extend h1b4 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 4, hash1)
| extend hash1_reversed = strcat(h1b4, h1b3, h1b2, h1b1)
| extend hash1_reversed_dec = tolong(strcat('0x',hash1_reversed))
| extend h2b1 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 1, hash2)
| extend h2b2 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 2, hash2)
| extend h2b3 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 3, hash2)
| extend h2b4 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 4, hash2)
| extend hash2_reversed = strcat(h2b4, h2b3, h2b2, h2b1)
| extend hash2_reversed_dec = tolong(strcat('0x',hash2_reversed))
| extend h3b1 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 1, hash3)
| extend h3b2 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 2, hash3)
| extend h3b3 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 3, hash3)
| extend h3b4 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 4, hash3)
| extend hash3_reversed = strcat(h3b4, h3b3, h3b2, h3b1)
| extend hash3_reversed_dec = tolong(strcat('0x',hash3_reversed))
| extend h4b1 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 1, hash4)
| extend h4b2 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 2, hash4)
| extend h4b3 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 3, hash4)
| extend h4b4 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 4, hash4)
| extend hash4_reversed = strcat(h4b4, h4b3, h4b2, h4b1)
| extend hash4_reversed_dec = tolong(strcat('0x',hash4_reversed))
| extend h5b1 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 1, hash5)
| extend h5b2 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 2, hash5)
| extend h5b3 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 3, hash5)
| extend h5b4 = extract(@"(\w\w)(\w\w)(\w\w)(\w\w)", 4, hash5)
| extend hash5_reversed = strcat(h5b4, h5b3, h5b2, h5b1)
| extend hash5_reversed_dec = tolong(strcat('0x',hash5_reversed))
| extend SID = strcat("S-1-5-80-", hash1_reversed_dec, "-", hash2_reversed_dec, "-", hash3_reversed_dec, "-", hash4_reversed_dec, "-", hash5_reversed_dec)
//| summarize by Activity
| project target_service, SID
| join kind=rightouter ( 
SecurityEvent
| where EventID == 4670
| extend OldSd = extract("<Data Name=\"OldSd\">(.*)</Data>", 1, EventData)
| extend OldSd = todynamic(replace(")\"]","\"]",tostring(split(replace("D:\\w+(","",OldSd), ")("))))
| extend NewSd = extract("<Data Name=\"NewSd\">(.*)</Data>", 1, EventData)
| extend NewSd = todynamic(replace(")\"]","\"]",tostring(split(replace("D:\\w+(","",NewSd), ")("))))
| mv-expand NewSd
| where NewSd contains "S-1-5-80"
| extend SID = extract(@".*(S-1-5-80-\d+-\d+-\d+-\d+-\d+)", 1, tostring(NewSd))
| extend AllowDeny = replace("D", "Deny", replace("A", "Allow", extract(@"(A|D)(\w|;)+(S-1-5-80-\d+-\d+-\d+-\d+-\d+)", 1, tostring(NewSd))))
| where isnotempty(AllowDeny)
) on SID
| project-away SID
| project-rename SID = SID1
| where ObjectName contains "kernel32.dll" and AllowDeny contains "deny"
| project-reorder TimeGenerated, ObjectName, AllowDeny, ProcessName, target_service, SID, OldSd, NewSd
```

## Potentially Suspicious Kernel32.dll Access 
```
SecurityEvent
| where EventID == 4663
| where ObjectName contains @"C:\Windows\System32\kernel32.dll"
```
