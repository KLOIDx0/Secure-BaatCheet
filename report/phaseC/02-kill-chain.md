# Rhadamanthys: Kill Chain Mapping

| Stage | What Rhadamanthys does | Source |
|---|---|---|
| Reconnaissance | Picks lures for groups likely to run cracked software or cheats, such as gamers (Roblox) and Adobe users. Targeting is by category, not by named victim. | Source 1, "Network Statistics" |
| Weaponization | Packs the payload into a lure: a password-protected archive with a setup.exe, a fake MSIX installer disguised as Chrome or Webex, or an LNK file that runs PowerShell. | Source 1, "Campaign I"; Source 2, pp. 9-10 |
| Delivery | Sent by phishing email as a ZIP, RAR, or LNK file, or posted on YouTube with links to MediaFire, Dropbox, Google Drive, or phishing pages. | Source 2, pp. 9, 27 (T1566); Source 1, "YouTube Ghost Network" |
| Exploitation | Not described in sources as exploiting a software flaw. Infection relies on the user running the file (T1204), often after being told to disable Windows Defender. | Source 2, p. 27 (T1204); Source 1, "Campaign I" |
| Installation | Three-stage loader: stage 1 unpacks shellcode, stage 2 injects into processes and checks for analysis tools, and stage 3 runs the stealers. Also drops an MSI in %LOCALAPPDATA%\Microsoft\ and writes a registry value to prevent re-running. | Source 2, pp. 10-12, 16 |
| Command and Control | Talks to its C2 server over HTTP or HTTPS to blend in with normal traffic. The C2 address changes every few days. | Source 2, pp. 6, 28 (T1071); Source 1, "Campaign II" |
| Actions on Objectives | Steals browser passwords, cookies, crypto wallets, email and FTP credentials, and RDP logins. Runs plug-ins: a keylogger, a clipboard swapper for crypto addresses, and a reverse proxy. Uses OCR to find seed phrases in images. | Source 2, pp. 6, 8, 20, 23-24 |
