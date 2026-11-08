# PROTOCOL.md

Port: 8080
Host: localhost (lab: set later)
Framing: one message per line, base64-encoded, terminated by \n
Key exchange: Diffie-Hellman, parameters: [TBD]
Cipher: AES, mode: [TBD], key size: [TBD]
Login/register: username + password, sent after key exchange
Credential file: username:salt_hex:hash_hex
Password hash: [TBD: e.g. SHA-256 for now, to be replaced in Step 40-ish]
Message to user: "to:<username>|<text>"
Server reply format: "from:<username>|<text>"
Quit command: "bye"
Error message: "error|<reason>
Success: "ok"
