rules:
- case_sensitive: false
  description: Détecte des tentatives d'injection SQL potentielles
  name: Suspicious_SQL_Injection
  patterns:
  - UNION\s+SELECT
  - '''\s+OR\s+''1''=''1'
  - '''\s*;\s*DROP\s+TABLE'
  - '''\s+OR\s+1=1--'
  - admin'--
  - 1'\s+UNION\s+SELECT\s+NULL
  severity: HIGH
- case_sensitive: false
  description: Détecte des tentatives de Cross-Site Scripting (XSS)
  name: Suspicious_XSS_Attempt
  patterns:
  - <script>
  - 'javascript:'
  - onerror=
  - onload=
  - <iframe
  - document\.cookie
  severity: MEDIUM
- case_sensitive: false
  description: Détecte des tentatives d'injection de commandes
  name: Suspicious_Command_Injection
  patterns:
  - ;/bin/sh
  - \|/bin/bash
  - '&&\s+cat\s+/etc/passwd'
  - \|\s+nc\s+
  - /bin/ls
  - wget\s+http
  - curl\s+http
  severity: HIGH
- case_sensitive: false
  description: Détecte des tentatives de path traversal
  name: Suspicious_Path_Traversal
  patterns:
  - \.\./\.\./\.\./
  - \.\.\\.\.\\.\.
  - /etc/passwd
  - /etc/shadow
  - c:\\windows\\system32
  severity: MEDIUM
- case_sensitive: false
  description: Détecte des User-Agent suspects associés à des malwares
  name: Malware_UserAgent
  patterns:
  - Gh0st
  - ZmEu
  - Nikto
  - sqlmap
  - Metasploit
  - python-requests/2\.6
  severity: HIGH
- case_sensitive: false
  description: Détecte le transfert de fichiers exécutables suspects
  name: Suspicious_Executable_Transfer
  patterns:
  - \.exe
  - \.dll
  - \.scr
  - \.bat
  - \.vbs
  - \.ps1
  severity: CRITICAL
- case_sensitive: false
  description: Détecte des payloads encodés suspects
  name: Suspicious_Encoded_Payload
  patterns:
  - eval\s*\(
  - base64_decode
  - FromBase64String
  - atob\(
  severity: MEDIUM
- case_sensitive: false
  description: Détecte des indicateurs de reverse shell
  name: Suspicious_Reverse_Shell
  patterns:
  - /bin/bash\s+-i
  - nc\s+-e\s+/bin/sh
  - bash\s+-c
  - python\s+-c\s+['"]import\s+socket
  - perl\s+-e\s+['"]use\s+Socket
  - /dev/tcp/
  severity: CRITICAL
- case_sensitive: false
  description: Détecte des fuites potentielles d'identifiants
  name: Suspicious_Credentials_Leak
  patterns:
  - password=
  - passwd=
  - pwd=
  - api_key=
  - apikey=
  - token=
  - Authorization:\s+Bearer
  severity: HIGH
- case_sensitive: false
  description: Détecte des patterns de scan de ports
  name: Suspicious_Port_Scan
  patterns:
  - nmap
  - masscan
  severity: LOW
