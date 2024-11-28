
# SentinelOne Deep Visibility Queries

## 1. cmd.exe with .cmd
```sql
query=Process AND process_cmdline contains "cmd.exe" AND process_cmdline contains ".cmd"
```

---

## 2. findstr.exe with switches
```sql
query=Process AND process_name="findstr.exe" AND (process_cmdline contains "/I" OR process_cmdline contains "/V")
```

---

## 3. tasklist.exe
```sql
query=Process AND process_name="tasklist.exe"
```

---

## 4. cmd with [InternetShortcut] and redirection (>)
```sql
query=Process AND process_cmdline contains "cmd" AND process_cmdline contains "[InternetShortcut]" AND process_cmdline contains ">"
```

---

## 5. cmd with md command
```sql
query=Process AND process_cmdline contains "cmd" AND process_cmdline contains "md"
```

---

## 6. cmd with /c copy /b
```sql
query=Process AND process_cmdline contains "cmd" AND process_cmdline contains "/c" AND process_cmdline contains "copy" AND process_cmdline contains "/b"
```

---

## 7. OpenWith.exe initiating AutoIt
```sql
query=Process AND parent_process_name="OpenWith.exe" AND process_original_filename contains "AutoIt"
```

---

## 8. OOBE-Maintenance with OpenWith.exe
```sql
query=Process AND process_name="OOBE-Maintenance" AND parent_process_name="OpenWith.exe"
```

---

## 9. dllhost with WMPNSCFG
```sql
query=Network AND process_cmdline contains "dllhost" AND parent_process_name="WMPNSCFG"
```

---

## 10. Almost.cmd, Internet.pif, InnoWave, or specific SHA256
```sql
query=File AND (file_name in ["Almost.cmd", "Internet.pif", "InnoWave"] OR file_sha256="a841624b9936a625f45cfffc446271be2191c3204bf7baa7bdf8890e6db691f3")
```

---

## 11. Network connection to specific IP address
```sql
query=Network AND remote_ip="144.76.133.166"
```
