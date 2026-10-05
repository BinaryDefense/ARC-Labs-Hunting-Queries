// Log source coverage: which NetScaler log classes reach Sentinel 
let nodes = dynamic(["<NSIP nodes>"]); 
Syslog 
| where Computer in (nodes) 
| extend Class = case( 
    SyslogMessage matches regex @"""(GET|POST|HEAD|PUT)\s", "http_access", 
    SyslogMessage has_any ("httpd", "File does not exist", "PHP "), "http_error", 
    SyslogMessage has_any ("pitboss", "qat0", "kernel:"), "var_log_messages", 
    SyslogMessage has "veriexec", "veriexec", 
    SyslogMessage has "CMD_EXECUTED", "audit", 
    SyslogMessage has_any ("sshd", "Accepted", "session opened"), "ssh", 
    "ns_log_other") 
| summarize Events=count(), Last=max(TimeGenerated) by Computer, Class 
| order by Computer asc, Events desc 

// CVE-2026-88771: command injection in gateway authentication and session logs 
let nodes = dynamic(["<NSIP nodes>"]); 
Syslog 
| where Computer in (nodes) 
| where SyslogMessage has_any ("AAA", "SSLVPN") 
// some log paths URL-encode the injected field; decode before matching 
| extend d = coalesce(url_decode(SyslogMessage), SyslogMessage) 
// the crash message ns_monuploadd_err.pl greps for, with or without the word pitboss 
| extend Trigger = d has "pitboss" or d has "missed too many heartbeats" or d has "unexpectedly died" 
| extend Indicator = case( 
    d has "ctxs.receiver", "webshell_path", 
    d has "nsgclient18", "deb_webshell_url", 
    d has "doAuthentication", "doAuthentication_endpoint", 
    d contains "INDEX:", "index_marker", 
    Trigger and (d contains "${IFS}" or d has "b64decode"), "trigger_with_obfuscation", 
    Trigger and d matches regex @"[;|`]|\$\(|\b(sh|bash|curl|wget|fetch|base64)\b", "trigger_with_shell_syntax", 
    d contains "${IFS}" or d has "b64decode", "IFS_or_b64decode", 
    d matches regex @"Browser(_type)?\s+""?[A-Za-z0-9+/]{40,}={0,2}", "base64_user_agent", 
    "") 
| where isnotempty(Indicator) 
// benign: the HA file-sync daemon registers a pitboss watch at startup 
| where not(d has_all ("Adding pitboss watch", "nsfsyncd")) 
| extend ClientIP = extract(@"Client_ip\s+(\d{1,3}(?:\.\d{1,3}){3})", 1, d) 
| extend StageUrl = extract(@"(https?:/{1,2}[^\s;|`>${}]+)", 1, d) 
| project TimeGenerated, Computer, Indicator, ClientIP, StageUrl, d 
| order by TimeGenerated asc 

// Base64 payloads staged in HTTP User-Agent headers with the INDEX: marker, across MDE-enrolled hosts 
DeviceNetworkEvents 
| where ActionType == "HttpConnectionInspected" 
| where isnotempty(AdditionalFields) 
| extend fields = parse_json(AdditionalFields) 
| extend userAgent = tostring(fields.user_agent), method = tostring(fields.method), uri = tostring(fields.uri) 
| where userAgent contains "INDEX:" 
| extend B64 = extract(@"INDEX:([A-Za-z0-9+/]{12,}={0,2})", 1, userAgent) 
| where isnotempty(B64) 
| extend Decoded = replace_regex(base64_decode_tostring(B64), @"[^\x20-\x7E]", ".") 
| extend ShellHit = Decoded has_any ("chmod", "/bin/", "sh", "bash", "curl", "wget", "php", "httpd.conf", "echo", "base64") 
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort, method, uri, ShellHit, Decoded, userAgent 
| order by ShellHit desc, TimeGenerated asc 

// CVE-2026-88772: DTLS exploit-pattern handshake failures 
let nodes = dynamic(["<NSIP nodes>"]); 
Syslog 
| where Computer in (nodes) 
| where SyslogMessage has "SSL_HANDSHAKE_FAILURE" and SyslogMessage has "DTLSv1.0" and SyslogMessage has "Internal Error" 
| extend ClientIP  = extract(@"ClientIP\s+(\d{1,3}(?:\.\d{1,3}){3})", 1, SyslogMessage) 
| extend VserverIP = extract(@"VserverServiceIP\s+(\d{1,3}(?:\.\d{1,3}){3})", 1, SyslogMessage) 
| summarize Hits=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by Computer, ClientIP, VserverIP 
| order by Hits desc 

