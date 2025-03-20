# Initial Architecture

## TODO:

- [x] mDNS Registering & Browsing
  - [x] Broadcast service
  - [x] Find other clients
  - [x] Store clients in a way that's accessible to the main logic (for further communication)
  - [x] Run in a background thread and shutdown gracefully
- [ ] TCP p2p Communication
  - [ ] Send & Receive introduction message (RSA Public Keys)
  - [ ] Send & Receive key change message (RSA Public Keys)
  - [ ] Send & Receive file_list request
  - [ ] Send file upload request
  - [ ] Send file download request
  - [ ] Accept file upload request
  - [ ] Accept file download request
- [ ] RSA & DHE Encryption
  - [ ] Generate new RSA keys
  - [ ] Encrypt initial messages with RSA
  - [ ] Determine AES Session keys over RSA protected messages
  - [ ] Encrypt later messages with AES
  - [ ] Store RSA keys in password-protected file
  - [ ] Store local files in password-protected files
- [ ] CLI User Interaction
  - [ ] Help command
  - [ ] Send files to specific peer
  - [ ] Consent to requests (sending and receiving)
  - [ ] Manage contacts
  - [ ] Manage files
  - [ ] Make it fancier

## State to store:

- mDNS client IP addresses (owned by mDNS thread)
  - Send 1 way to TCP
- TCP client list (owned by TCP thread)
  - mDNS doesn't need access
  - Commandline needs read only access (maybe update client names?)
- Encryption keys
  - Owned by TCP thread
- Instructions (owned by CommandLine)
  - TCP thread needs user approval for certain actions
  - Send and receive commands to TCP

## First try:

- Main loop that receives commands and enters different modes
- Mostly Single thread
- Sending files enters mdns browsing mode
- Receiving files enters mdns broadcasting mode & TCP accepting mode
-

## Final try:

- Main loop that receives commands and lets you select different modes (maybe fancier than typing commands/ratatui?)
- Background threads of mDNS and TCP receiving
  - Should be exchanging keys & responding to file_list requests in the background
-
