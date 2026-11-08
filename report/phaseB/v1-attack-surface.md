# v1 Attack Surface: Baseline (v1-baseline)

Scope: the team's own baseline build, tested only in the isolated lab.
Method: entry-point enumeration from code review (CY2004 Phase B, CLO1).

| ID | Entry point | File and function | Who can reach it | What goes in or out |
|---|---|---|---|---|
| S1 | TCP port 8080 | `server.py`, `main()` | Anyone who can reach the host. Binds to all interfaces (`''`), not only localhost. | Opens connections |
| S2 | DH public value A (first message) | `server.py`, `handle_client()`; `client.py`, `main()` | Anyone who can connect, before any login. Sent unauthenticated. | Client's public value A |
| S3 | DH public value B (reply) | `client.py`, `main()`; `server.py`, `handle_client()` | Anyone on the path between client and server | Server's public value B, unsigned |
| S4 | Frame reader | `recv_msg()` in `client.py` and `server.py` | Any connected peer | Reads one line of any length into memory. No size limit. |
| S5 | Login and register messages | `server.py`, `do_auth()`; `client.py`, login loop | Any connected peer | `cmd\|user\|pw`, encrypted with K. Three tries per connection; a client can reconnect and try again. |
| S6 | Password field | `client.py`, login loop (`input("Password: ")`); `auth.py`, `valid_credentials()` | The user at the keyboard, and anyone looking at the screen | Typed password, shown on screen. No minimum length or strength check. |
| S7 | Username field | `auth.py`, `valid_credentials()`, `register()` | Any connected peer | Name. Length and characters checked, but any unused name can be claimed. |
| S8 | Login response timing | `auth.py`, `verify_login()` | Any connected peer | Unknown user returns at once; known user runs the hash first. Response time reveals whether a name exists. |
| S9 | Credential file | `auth.py`, `CRED_FILE` (`users.txt`) | Anyone with read access to the host's files | Usernames, salts, and SHA-256 hashes. Default file permissions. A malformed line makes `find_user()` crash. |
| S10 | Chat routing message | `server.py`, `handle_client()` chat loop; `route()` | Any logged-in user | `to:<user>\|<text>`. No length limit, no rate limit. |
| S11 | Delivered message | `client.py`, `receiver()` | Any logged-in user who sends to you | `from:<user>\|<text>`, printed raw to the terminal. Terminal escape codes in the text are not stripped. |
| S12 | Online table | `server.py`, `online`, `do_auth()` | Users with a valid password | Login rejects a second session for a name already online. Needs the valid password first, so it gives no new access. |
| S13 | Decryption step | `crypto_util.py`, `decrypt()`; called from `handle_client()`, `receiver()`, `do_auth()` | Any connected peer | Bad data raises an exception. No `try` around it, so the handling thread stops. |

## Notes for the next step

- S2, S3, and S8 are the entry points for the expected baseline findings: unauthenticated key exchange, fast password hash, and an observable timing difference.
- S4, S5, S10, and S13 are denial-of-service and input-handling candidates. Phase B scores them with CVSS.
- This table lists entry points only. Scoring, CWE mapping, and CIA impact come in the next step.
