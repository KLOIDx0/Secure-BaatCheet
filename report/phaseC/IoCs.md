   # Rhadamanthys IoCs

   Sources: Source 1 (Check Point Research, 23 Oct 2025) and Source 2 (Recorded Future, MTP-2024-0926, 26 Sep 2024).
   Note: URLs are defanged (hxxps, [.]) so they cannot be clicked by accident.

   ## Host-based (what to look for on a computer)

   | Type | Value | Source |
   |---|---|---|
   | Registry value | HKCU\SOFTWARE\SibCode\sn2 (v0.7.0; older versions use \sn) | Source 2, p. 16 |
   | Dropped MSI | Random name in %LOCALAPPDATA%\Microsoft\, run with ShellExecuteExW | Source 2, p. 12 |
   | Mutex | Global\MSCTF.Asm.{04fb3f26-9d18-66b5-6862-7b8a85e4b620} (plus 8 session variants) | Source 2, Table 3, p. 14 |
   | Mutex | MSCTF.Asm.{00000009-4fb3f26-9d18-66b568-627b8a85e4b6} | Source 2, Table 3, p. 14 |

   ## File hashes (SHA-256, from Source 1)

   | File | SHA-256 |
   |---|---|
   | Campaign I, Set-up.exe (Rhadamanthys) | b429a3e21a3ee5ac7be86739985009647f570548b4f04d4256139bc280a6c68f |
   | Campaign II, Set-Up.msi | ad81b2f47eefcdce16dfa85d8d04f5f8b3b619ca31a14273da6773847347bec8 |

   ## Network (C2 servers, defanged)

   | Campaign | C2 address | Source |
   |---|---|---|
   | I | hxxps://94.74.164[.]157:8888/gateway/6xomjoww.1hj7n | Source 1 |
   | II | hxxps://5.252.155[.]99/gateway/r2sh55wm.a56d3 | Source 1 |
