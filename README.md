# MMS MITM PDU Extractor

A Man-in-the-Middle framework for intercepting, delaying, and extracting MMS (Manufacturing Message Specification) PDUs over ISO-on-TCP (RFC 1006).

This project operates inline using NetfilterQueue and Scapy to intercept live MMS traffic (TCP/102), extract raw MMS PDUs, and parse them using a custom BER-TLV parser.

---

## Features (Current State)

- Inline MITM interception using NetfilterQueue
- TCP sequence/acknowledgment adjustment support
- TPKT (RFC 1006) parsing
- COTP header stripping
- Automatic ISO Session / Presentation depth handling
- MMS PDU extraction independent of ISO wrapping
- Raw MMS PDU hex dump
- BER-TLV recursive parser
- Pretty-print structured MMS tree
- Flow tracking per TCP session

---

## Protocol Stack Handled

The extractor correctly skips the following layers:

TCP  
→ TPKT (RFC 1006)  
→ COTP (Connection-Oriented Transport Protocol)  
→ ISO Session  
→ ISO Presentation  
→ ACSE (when present)  
→ MMS PDU  

The MMS PDU is extracted automatically without relying on fixed offsets.

---

## Example Extracted MMS PDU
```bash
$ sudo python -m mitm.mms_delay_inject

===== MMS PDU HEX =====
a02fa02d02010ea628a026a1241a1173696d706c65494f47656e65726963494f1a0f4747494f3124434f24535043534f34
Confirmed-RequestPDU (len=47)
  Confirmed-RequestPDU (len=45)
    INTEGER (len=1)
     Value: 14
    Tag-6 (len=40)
      Confirmed-RequestPDU (len=38)
        Confirmed-ResponsePDU (len=36)
          Tag-26 (len=17)
           Value: b'simpleIOGenericIO'
          Tag-26 (len=15)
           Value: b'GGIO1$CO$SPCSO4'
```

---

## Architecture Overview

1. Intercept TCP packets on port 102
2. Identify TPKT frames
3. Strip:
   - TPKT header (4 bytes)
   - COTP header
4. Parse remaining BER structure
5. Locate first MMS context-specific constructed PDU
6. Extract exact raw byte slice using start/end offsets
7. Print:
   - Hex encoding
   - Structured TLV tree

---

## Technologies Used

- Python 3
- Scapy
- NetfilterQueue
- Custom BER-TLV recursive parser

---

## Current Status

This version focuses on:

- Reliable MMS PDU extraction
- Structural parsing
- Flow stability
- No packet dropping

Injection and mutation logic will be added in future revisions.

---

## Disclaimer

This project is intended for research and educational purposes in industrial protocol security analysis.

Do not use against systems without proper authorization.
