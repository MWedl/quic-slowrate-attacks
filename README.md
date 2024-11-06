# Slow Rate DoS Attack Scripts against QUIC, HTTP/3 and DoQ
Attack scripts to exploit slow rate denial of service against QUIC-based protocols (HTTP/3 and DoQ).
Created during research for my master's thesis.


Following slow rate DoS attack vectors are implemented:
* QUIC
    * Keeping Connections Open via `PING` Frames
    * Slow Write in `CRYPTO` Stream during QUIC 1-RTT Handshake
    * Slow Read by Gradually Increasing Connection-Wide Flow Control Windows
    * Slow Read by Gradually Increasing Per-Stream Flow Control Windows
* HTTP/3
    * HTTP/3 Slow Write inside `HEADERS` Frame
    * HTTP/3 Slow Write via Delay between `HEADERS` and `DATA` Frames
    * HTTP/3 Slow Write inside `DATA` Frame
    * HTTP/3 Slow Write via Delays between multiple `DATA` Frames
    * HTTP/3 Slow Write inside QPACK Dynamic Table Inserts
    * HTTP/3 Slow Write via delayed QPACK Dynamic Table Inserts
* DoQ
    * DoQ Slow Write inside DNS Queries
