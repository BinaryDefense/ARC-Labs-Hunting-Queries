# Network connections to SVG files with Outlook as the initiating or parent process

DeviceNetworkEvents| where InitiatingProcessParentFileName contains "outlook.exe"| where RemoteUrl endswith ".svg"

DeviceNetworkEvents| where InitiatingProcessFileName contains "outlook.exe"| where RemoteUrl endswith ".svg"

# SVG URLs that redirect to additional URLs

UrlClickEvents| where todynamic(UrlChain)[0] endswith ".svg"| where array_length(todynamic(UrlChain)) > 1

# SVG file creation from Outlook activity

DeviceFileEvents| where InitiatingProcessFileName contains "outlook.exe"| where FileName endswith ".svg"| project-reorder TimeGenerated, DeviceName, FileName, SHA256, FileOriginUrl