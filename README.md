# Security Protocol and Data Model (SPDM) Initial Authentication Communication Flow

## Table of Contents
- [Introduction](#introduction)
- [SPDM Overview](#spdm-overview)
- [SPDM over MCTP](#spdm-over-mctp)
- [Initial Authentication Flow](#initial-authentication-flow)
  - [Connection Phase](#connection-phase)
  - [Authentication Phase](#authentication-phase)
  - [Session Establishment Phase](#session-establishment-phase)
- [SPDM Message Format](#spdm-message-format)
- [SPDM over MCTP Message Format](#spdm-over-mctp-message-format)
- [SPDM Commands and Response Codes](#spdm-commands-and-response-codes)
- [Error Handling](#error-handling)
- [Security Considerations](#security-considerations)
- [GET_VERSION Command](#get_version-command)
  - [Purpose and Functionality](#purpose-and-functionality)
  - [Message Format](#message-format)
  - [Protocol Flow](#protocol-flow)
  - [State Management](#state-management)
  - [Error Handling](#error-handling-1)
  - [Retry Behavior](#retry-behavior)
  - [Implementation Considerations](#implementation-considerations)
  - [GET_VERSION Examples](#get_version-examples)
- [GET_CAPABILITIES Command](#get_capabilities-command)
  - [Purpose and Functionality](#purpose-and-functionality-1)
  - [Message Format](#message-format-1)
  - [Capability Flags](#capability-flags)
  - [Protocol Flow](#protocol-flow-1)
  - [State Management](#state-management-1)
  - [Error Handling](#error-handling-2)
  - [Retry Behavior](#retry-behavior-1)
  - [Implementation Considerations](#implementation-considerations-1)
  - [GET_CAPABILITIES Examples](#get_capabilities-examples)
- [NEGOTIATE_ALGORITHMS Command](#negotiate_algorithms-command)
  - [Purpose and Functionality](#purpose-and-functionality-2)
  - [Message Format](#message-format-2)
  - [Algorithm Types](#algorithm-types)
  - [Protocol Flow](#protocol-flow-2)
  - [State Management](#state-management-2)
  - [Error Handling](#error-handling-3)
  - [Retry Behavior](#retry-behavior-2)
  - [Implementation Considerations](#implementation-considerations-2)
  - [NEGOTIATE_ALGORITHMS Examples](#negotiate_algorithms-examples)
- [GET_DIGESTS Command](#get_digests-command)
  - [Purpose and Functionality](#purpose-and-functionality-3)
  - [Message Format](#message-format-3)
  - [Certificate Chain Slots](#certificate-chain-slots)
  - [Protocol Flow](#protocol-flow-3)
  - [State Management](#state-management-3)
  - [Error Handling](#error-handling-4)
  - [Retry Behavior](#retry-behavior-3)
  - [Implementation Considerations](#implementation-considerations-3)
  - [GET_DIGESTS Examples](#get_digests-examples)
- [GET_CERTIFICATE Command](#get_certificate-command)
  - [Purpose and Functionality](#purpose-and-functionality-4)
  - [Message Format](#message-format-4)
  - [Certificate Chain Format](#certificate-chain-format)
  - [Protocol Flow](#protocol-flow-4)
  - [State Management](#state-management-4)
  - [Error Handling](#error-handling-5)
  - [Retry Behavior](#retry-behavior-4)
  - [Implementation Considerations](#implementation-considerations-4)
  - [GET_CERTIFICATE Examples](#get_certificate-examples)
- [CHALLENGE Command](#challenge-command)
  - [Purpose and Functionality](#purpose-and-functionality-5)
  - [Message Format](#message-format-5)
  - [Signature Generation](#signature-generation)
  - [Protocol Flow](#protocol-flow-5)
  - [State Management](#state-management-5)
  - [Error Handling](#error-handling-6)
  - [Retry Behavior](#retry-behavior-5)
  - [Implementation Considerations](#implementation-considerations-5)
  - [CHALLENGE Examples](#challenge-examples)
- [KEY_EXCHANGE Command](#key_exchange-command)
  - [Purpose and Functionality](#purpose-and-functionality-6)
  - [Message Format](#message-format-6)
  - [Key Derivation](#key-derivation)
  - [Protocol Flow](#protocol-flow-6)
  - [State Management](#state-management-6)
  - [Error Handling](#error-handling-7)
  - [Retry Behavior](#retry-behavior-6)
  - [Implementation Considerations](#implementation-considerations-6)
  - [KEY_EXCHANGE Examples](#key_exchange-examples)
- [FINISH Command](#finish-command)
  - [Purpose and Functionality](#purpose-and-functionality-7)
  - [Message Format](#message-format-7)
  - [Verify Data Generation](#verify-data-generation)
  - [Protocol Flow](#protocol-flow-7)
  - [State Management](#state-management-7)
  - [Error Handling](#error-handling-8)
  - [Retry Behavior](#retry-behavior-7)
  - [Implementation Considerations](#implementation-considerations-7)
  - [FINISH Examples](#finish-examples)
- [Decoding SPDM over MCTP Messages](#decoding-spdm-over-mctp-messages)
- [References](#references)

## Introduction

The Security Protocol and Data Model (SPDM) is a standard developed by the Distributed Management Task Force (DMTF) that defines a communication protocol for device authentication, firmware measurements, and session key establishment. SPDM enables secure communication between components in a system, providing a standardized way to verify the identity and integrity of hardware components.

This document focuses on the SPDM initial authentication communication flow when transported over the Management Component Transport Protocol (MCTP), detailing the message exchanges, formats, and security considerations for establishing authenticated and secure communication channels between SPDM Requesters and Responders.

## SPDM Overview

SPDM is defined in the DMTF specification DSP0274 and provides the following key capabilities:

1. **Device Authentication**: Verifies the identity of devices using certificates and challenge-response mechanisms
2. **Firmware Measurements**: Retrieves and validates measurements of device firmware
3. **Session Establishment**: Creates secure sessions with encrypted communication
4. **Key Exchange**: Negotiates cryptographic keys for secure communication

SPDM defines two roles:
- **Requester**: Initiates SPDM communication and requests information or actions
- **Responder**: Receives SPDM requests and provides responses

The SPDM protocol operates in three main phases:
1. **Connection Phase**: Establishes basic communication parameters
2. **Authentication Phase**: Verifies the identity of the Responder (and optionally the Requester)
3. **Session Establishment Phase**: Creates a secure session for encrypted communication

## SPDM over MCTP

The Management Component Transport Protocol (MCTP) is a communication protocol defined by DMTF in specification DSP0236 that provides a transport mechanism for communication between management controllers and managed devices. SPDM can be transported over MCTP as defined in the DMTF specification DSP0275 "Security Protocol and Data Model (SPDM) over MCTP Binding Specification."

Key characteristics of SPDM over MCTP include:

1. **Message Type**: SPDM messages are identified by the MCTP message type 0x05
2. **Message Format**: MCTP adds a transport header to SPDM messages
3. **Message Size**: MCTP has a maximum message size that may require SPDM messages to be chunked
4. **Secured Messages**: Secured SPDM messages over MCTP follow the format defined in DSP0276

## Initial Authentication Flow

The SPDM initial authentication flow consists of a sequence of message exchanges between the Requester and Responder to establish a secure and authenticated connection. The flow can be divided into three phases:

```
+-------------+                                  +-------------+
|  Requester  |                                  |  Responder  |
+-------------+                                  +-------------+
      |                                                |
      |                GET_VERSION                     |
      |----------------------------------------------->|
      |                                                |
      |                  VERSION                       |
      |<-----------------------------------------------|
      |                                                |
      |              GET_CAPABILITIES                  |
      |----------------------------------------------->|
      |                                                |
      |                CAPABILITIES                    |
      |<-----------------------------------------------|
      |                                                |
      |            NEGOTIATE_ALGORITHMS                |
      |----------------------------------------------->|
      |                                                |
      |                ALGORITHMS                      |
      |<-----------------------------------------------|
      |                                                |
- - - | - - - - - - - - - - - - - - - - - - - - - - - -|- - - - - - - -
      |                                                |
 If   |                GET_DIGESTS                     |
 supported |----------------------------------------------->|
      |                                                |
      |                  DIGESTS                       |
      |<-----------------------------------------------|
      |                                                |
- - - | - - - - - - - - - - - - - - - - - - - - - - - -|- - - - - - - -
      |                                                |
 If   |              GET_CERTIFICATE                   |
 necessary |----------------------------------------------->|
      |                                                |
      |                CERTIFICATE                     |
      |<-----------------------------------------------|
      |                                                |
- - - | - - - - - - - - - - - - - - - - - - - - - - - -|- - - - - - - -
      |                                                |
 If   |                 CHALLENGE                      |
 supported |----------------------------------------------->|
      |                                                |
      |               CHALLENGE_AUTH                   |
      |<-----------------------------------------------|
      |                                                |
- - - | - - - - - - - - - - - - - - - - - - - - - - - -|- - - - - - - -
      |                                                |
 If   |             GET_MEASUREMENTS                   |
 supported |----------------------------------------------->|
      |                                                |
      |               MEASUREMENTS                     |
      |<-----------------------------------------------|
      |                                                |
- - - | - - - - - - - - - - - - - - - - - - - - - - - -|- - - - - - - -
      |                                                |
 If   |               KEY_EXCHANGE                     |
 supported |----------------------------------------------->|
      |                                                |
      |             KEY_EXCHANGE_RSP                   |
      |<-----------------------------------------------|
      |                                                |
      |=================================================|
      |                                                |
      |<------------Mutual Authentication------------->|
      |                                                |
      |                  FINISH                        |
      |----------------------------------------------->|
      |                                                |
      |                FINISH_RSP                      |
      |<-----------------------------------------------|
      |                                                |
      |<-------------Application Data----------------->|
      |                                                |
      |                Secure Session                  |
      |=================================================|
      |                                                |
```

### Connection Phase

The connection phase establishes the basic parameters for SPDM communication:

1. **GET_VERSION**
   - Requester sends GET_VERSION to discover supported SPDM versions
   - Responder replies with VERSION indicating supported versions
   - Purpose: Version negotiation

2. **GET_CAPABILITIES**
   - Requester sends GET_CAPABILITIES to discover supported features
   - Responder replies with CAPABILITIES indicating supported features
   - Purpose: Feature discovery and negotiation

3. **NEGOTIATE_ALGORITHMS**
   - Requester sends NEGOTIATE_ALGORITHMS to propose cryptographic algorithms
   - Responder replies with ALGORITHMS indicating selected algorithms
   - Purpose: Cryptographic algorithm negotiation

### Authentication Phase

The authentication phase verifies the identity of the Responder (and optionally the Requester):

1. **GET_DIGESTS**
   - Requester sends GET_DIGESTS to request certificate chain digests
   - Responder replies with DIGESTS containing certificate chain digests
   - Purpose: Discover available certificate slots

2. **GET_CERTIFICATE**
   - Requester sends GET_CERTIFICATE to request a certificate chain
   - Responder replies with CERTIFICATE containing the certificate chain
   - Purpose: Retrieve certificate for verification
   - Note: May require multiple exchanges for large certificates

3. **CHALLENGE**
   - Requester sends CHALLENGE with a random nonce
   - Responder replies with CHALLENGE_AUTH containing a signature over the nonce and transcript
   - Purpose: Verify Responder identity and establish trust
   - Note: May include request for mutual authentication

### Session Establishment Phase

The session establishment phase creates a secure session for encrypted communication:

1. **KEY_EXCHANGE**
   - Requester sends KEY_EXCHANGE with key exchange data
   - Responder replies with KEY_EXCHANGE_RSP with its key exchange data and a signature
   - Purpose: Establish session keys for secure communication

2. **FINISH**
   - Requester sends FINISH with a signature over the transcript
   - Responder replies with FINISH_RSP
   - Purpose: Complete session establishment and verify Requester identity

Alternatively, for Pre-Shared Key (PSK) based sessions:

1. **PSK_EXCHANGE**
   - Requester sends PSK_EXCHANGE with PSK context
   - Responder replies with PSK_EXCHANGE_RSP
   - Purpose: Establish session keys using pre-shared keys

2. **PSK_FINISH**
   - Requester sends PSK_FINISH
   - Responder replies with PSK_FINISH_RSP
   - Purpose: Complete PSK-based session establishment

## SPDM Message Format

SPDM messages follow a common format:

```
+----------------+----------------+----------------+
| SPDM Header    | Message Body   | Optional Data  |
+----------------+----------------+----------------+
```

**SPDM Header (1 byte)**:
- Bits 7-4: SPDM version (0001b for SPDM 1.0, 0010b for SPDM 1.1, etc.)
- Bits 3-0: Request/Response code

**Message Body**:
- Request-specific or response-specific fields
- Variable length depending on the message type

**Optional Data**:
- Additional data such as signatures, certificates, or measurements
- Variable length depending on the message type

## SPDM over MCTP Message Format

When SPDM is transported over MCTP, the message format is:

```
+----------------+----------------+----------------+----------------+
| MCTP Header    | SPDM Header    | SPDM Body      | Optional Data  |
+----------------+----------------+----------------+----------------+
```

**MCTP Header (1 byte)**:
- Bit 7: D-bit (Direction bit)
- Bits 6-0: Message Type (0x05 for SPDM)

For secured messages in a session, the format is:

```
+----------------+----------------+----------------+----------------+----------------+----------------+
| MCTP Header    | Session ID     | Sequence Num   | Length         | Encrypted Data | MAC            |
+----------------+----------------+----------------+----------------+----------------+----------------+
```

- **Session ID**: 4 bytes identifying the session
- **Sequence Number**: 2 bytes for replay protection
- **Length**: 2 bytes indicating the length of the encrypted data
- **Encrypted Data**: The encrypted SPDM message
- **MAC**: Message Authentication Code for integrity verification

## SPDM Commands and Response Codes

| Command/Response | Code | Description |
|------------------|------|-------------|
| GET_VERSION      | 0x84 | Request supported SPDM versions |
| VERSION          | 0x04 | Response with supported versions |
| GET_CAPABILITIES | 0xE1 | Request supported capabilities |
| CAPABILITIES     | 0x61 | Response with supported capabilities |
| NEGOTIATE_ALGORITHMS | 0xE3 | Request to negotiate algorithms |
| ALGORITHMS       | 0x63 | Response with negotiated algorithms |
| GET_DIGESTS      | 0x81 | Request certificate digests |
| DIGESTS          | 0x01 | Response with certificate digests |
| GET_CERTIFICATE  | 0x82 | Request certificate chain |
| CERTIFICATE      | 0x02 | Response with certificate chain |
| CHALLENGE        | 0x83 | Challenge request for authentication |
| CHALLENGE_AUTH   | 0x03 | Challenge authentication response |
| KEY_EXCHANGE     | 0xE4 | Request to establish a session |
| KEY_EXCHANGE_RSP | 0x64 | Response to establish a session |
| FINISH           | 0xE5 | Request to complete session establishment |
| FINISH_RSP       | 0x65 | Response to complete session establishment |
| PSK_EXCHANGE     | 0xE6 | Request to establish a PSK session |
| PSK_EXCHANGE_RSP | 0x66 | Response to establish a PSK session |
| PSK_FINISH       | 0xE7 | Request to complete PSK session establishment |
| PSK_FINISH_RSP   | 0x67 | Response to complete PSK session establishment |
| ERROR            | 0x7F | Error response |

## Error Handling

SPDM defines an error handling mechanism using the ERROR response (0x7F). Error responses include:

| Error Code | Name | Description |
|------------|------|-------------|
| 0x01 | INVALID_REQUEST | The request is not valid in the current state |
| 0x02 | BUSY | The responder is busy and cannot process the request |
| 0x03 | UNEXPECTED_REQUEST | The request was not expected |
| 0x04 | UNSPECIFIED | An unspecified error occurred |
| 0x05 | UNSUPPORTED_REQUEST | The request is not supported |
| 0x06 | VERSION_MISMATCH | The SPDM version is not compatible |
| 0x07 | RESPONSE_NOT_READY | The response is not ready yet |
| 0x08 | REQUEST_RESYNCH | Request to resynchronize the session |
| 0x09 | VENDOR_DEFINED | Vendor-defined error |
| 0x0A | INVALID_RESPONSE_CODE | The response code is invalid |

When an error occurs, the Responder sends an ERROR response with the appropriate error code. The Requester may retry the request or take other actions based on the error code.

## Security Considerations

SPDM provides several security features to protect against various attacks:

1. **Message Transcript**: SPDM maintains a transcript of messages to prevent tampering
2. **Nonce**: Random values are used to prevent replay attacks
3. **Signatures**: Digital signatures verify the authenticity of messages
4. **Session Keys**: Secure sessions use encryption to protect message confidentiality
5. **Sequence Numbers**: Prevent replay attacks within a session

Security considerations for SPDM over MCTP include:

1. **Physical Security**: MCTP typically operates within a system, so physical security is important
2. **Transport Security**: MCTP itself does not provide encryption, so SPDM secured sessions are essential
3. **Implementation Vulnerabilities**: Implementations must be careful to avoid buffer overflows, timing attacks, etc.
4. **Key Management**: Proper management of certificates and keys is critical

## GET_VERSION Command

The GET_VERSION command is the first message in the SPDM protocol flow and is used to discover the SPDM versions supported by the Responder. This command must be sent before any other SPDM command and establishes the foundation for all subsequent communication.

### Purpose and Functionality

The GET_VERSION command serves several critical purposes in the SPDM protocol:

1. **Version Discovery**: Determines which SPDM versions are supported by the Responder
2. **Protocol Initialization**: Initiates the SPDM communication sequence
3. **Version Negotiation**: Enables the Requester and Responder to agree on a common SPDM version
4. **State Reset**: Resets the SPDM context and message transcripts

### Message Format

#### GET_VERSION Request

The GET_VERSION request has a fixed format as defined in the SPDM specification:

```
+----------------+----------------+----------------+----------------+
| SPDMVersion    | RequestResponseCode | Param1 (0x00)  | Param2 (0x00)  |
+----------------+----------------+----------------+----------------+
```

Detailed field breakdown:

| Byte offset | Field | Size (bytes) | Value | Description |
|------------|-------|--------------|-------|--------------|
| 0 | SPDMVersion | 1 | 0x10 | SPDM Version 1.0 |
| 1 | RequestResponseCode | 1 | 0x84 | GET_VERSION. See Table 4 — SPDM request codes |
| 2 | Param1 | 1 | 0x00 | Reserved |
| 3 | Param2 | 1 | 0x00 | Reserved |

**Important Notes**:
- The GET_VERSION request must always use SPDM version 1.0 (0x10) as the SPDMVersion field, regardless of the Requester's supported versions
- No additional data is included in the GET_VERSION request
- The total size of the GET_VERSION request is 4 bytes

#### VERSION Response

The VERSION response contains the list of SPDM versions supported by the Responder:

```
+----------------+----------------+----------------+----------------+----------------+----------------+
| SPDMVersion    | RequestResponseCode | Param1 (0x00)  | Param2 (0x00)  | Reserved       | VersionNumberEntryCount |
+----------------+----------------+----------------+----------------+----------------+----------------+
| VersionNumberEntry1 | VersionNumberEntry2 | ...            | VersionNumberEntry_n |
+----------------+----------------+----------------+----------------+
```

Detailed field breakdown:

| Byte offset | Field | Size (bytes) | Value | Description |
|------------|-------|--------------|-------|-------------|
| 0 | SPDMVersion | 1 | 0x10 | SPDM Version 1.0 |
| 1 | RequestResponseCode | 1 | 0x04 | VERSION. See Table 5 — SPDM response codes |
| 2 | Param1 | 1 | 0x00 | Reserved |
| 3 | Param2 | 1 | 0x00 | Reserved |
| 4 | Reserved | 1 | 0x00 | Reserved |
| 5 | VersionNumberEntryCount | 1 | n | Number of version entries present in this table (=n) |
| 6 | VersionNumberEntry1:n | 2×n | - | 16-bit version entries. See VersionNumberEntry definition below |

**VersionNumberEntry Definition (Table 10)**:
- Each version entry is a 16-bit value with the following bit allocation:

| Bit offset | Field | Description |
|------------|-------|-------------|
| [15:12] | MajorVersion | Version of the specification with changes that are incompatible with one or more functions in earlier major versions of the specification. |
| [11:8] | MinorVersion | Version of the specification with changes that are compatible with functions in earlier minor versions of this major version specification. |
| [7:4] | UpdateVersionNumber | Version of the specification with editorial updates and errata fixes. Informational; ignore when checking versions for interoperability. |
| [3:0] | Alpha | Pre-release work-in-progress version of the specification. Backward compatible with earlier minor versions of this major version specification. However, because the Alpha value represents an in-development version of the specification, versions that share the same major and minor version numbers but have different Alpha versions might not be fully interoperable. Released versions shall have an Alpha value of zero (0). |

**Common Version Values**:
- 0x10: SPDM 1.0
- 0x11: SPDM 1.1
- 0x12: SPDM 1.2
- 0x13: SPDM 1.3

### Protocol Flow

1. **Requester Action**:
   - The Requester constructs a GET_VERSION request message
   - The Requester sends the GET_VERSION request to the Responder
   - The Requester waits for a VERSION response

2. **Responder Action**:
   - The Responder receives the GET_VERSION request
   - The Responder validates the request format
   - The Responder constructs a VERSION response with its supported versions
   - The Responder sends the VERSION response to the Requester

3. **Version Negotiation**:
   - The Requester receives the VERSION response
   - The Requester validates the response format
   - The Requester compares its supported versions with the Responder's versions
   - The Requester selects the highest common version for subsequent communication

### State Management

The GET_VERSION command has significant effects on the SPDM state machine:

1. **State Reset**:
   - When a Responder receives a GET_VERSION request, it resets its internal state
   - All previous message transcripts are cleared
   - Any established session information is preserved

2. **Transcript Initialization**:
   - The GET_VERSION request and VERSION response are added to the transcript buffer A
   - This transcript is used for subsequent message authentication

3. **Connection State**:
   - After successful version negotiation, the connection state is set to NEGOTIATED
   - This allows the protocol to proceed to capability negotiation

### Error Handling

The GET_VERSION command can encounter several error conditions:

1. **Invalid Request Format**:
   - If the request size is incorrect (less than 6 bytes)
   - If the request contains invalid parameters
   - Response: ERROR with code INVALID_REQUEST (0x01)

2. **Version Mismatch**:
   - If the request uses an SPDM version other than 1.0
   - Response: ERROR with code VERSION_MISMATCH (0x06)

3. **Busy State**:
   - If the Responder is temporarily unable to process the request
   - Response: ERROR with code BUSY (0x02)
   - The Requester should retry after a delay

4. **Unexpected Request**:
   - If the request is received in an invalid state
   - Response: ERROR with code UNEXPECTED_REQUEST (0x03)

5. **No Common Version**:
   - If the Requester and Responder have no common SPDM version
   - Result: The Requester terminates the SPDM communication

### Retry Behavior

When the Requester receives an error response to a GET_VERSION request, it should follow these retry procedures:

1. **BUSY Error**:
   - Wait for the specified time (CT_EXPONENT) if provided
   - Retry the GET_VERSION request
   - Continue retrying until successful or retry limit is reached

2. **REQUEST_RESYNCH Error**:
   - Reset the local context
   - Restart the SPDM communication with GET_VERSION

3. **Other Errors**:
   - Terminate the SPDM communication
   - Report the error to higher layers

### Implementation Considerations

1. **Version Selection Strategy**:
   - Implementations should select the highest common version
   - If multiple versions are supported, list them in descending order

2. **Backward Compatibility**:
   - Responders should support SPDM 1.0 for maximum compatibility
   - Requesters should handle responses with multiple version entries

3. **Security Implications**:
   - The GET_VERSION exchange is not authenticated
   - Attackers could potentially downgrade the protocol version
   - Later authentication steps help mitigate this risk

4. **Performance Optimization**:
   - Implementations should cache negotiated versions
   - Repeated GET_VERSION requests should be minimized

### GET_VERSION Examples

**Request (MCTP + SPDM)**:
```
05 10 84 00 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `84`: RequestResponseCode (GET_VERSION)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)

**Response (MCTP + SPDM)**:
```
05 10 04 00 00 00 03 10 00 11 00 12 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `04`: RequestResponseCode (VERSION)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `03`: VersionNumberEntryCount (3 versions supported)
- `10 00`: SPDM version 1.0 in little-endian format
- `11 00`: SPDM version 1.1 in little-endian format
- `12 00`: SPDM version 1.2 in little-endian format

#### Error Response Example

**VERSION_MISMATCH Error Response (MCTP + SPDM)**:
```
05 10 7F 06 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `7F`: RequestResponseCode (ERROR)
- `06`: Error code (VERSION_MISMATCH)
- `00`: Error data

**BUSY Error Response (MCTP + SPDM)**:
```
05 10 7F 02 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `7F`: RequestResponseCode (ERROR)
- `02`: Error code (BUSY)
- `00`: Error data

#### Additional GET_VERSION Examples

**Example 1: GET_VERSION with Single Version Response**

Request (MCTP + SPDM):
```
05 10 84 00 00
```

Response (MCTP + SPDM):
```
05 10 04 00 00 00 01 10 00
```

Breakdown of Response:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `04`: RequestResponseCode (VERSION)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `01`: VersionNumberEntryCount (1 version supported)
- `10 00`: SPDM version 1.0 in little-endian format

**Example 2: GET_VERSION with Multiple Versions Including SPDM 1.3**

Request (MCTP + SPDM):
```
05 10 84 00 00
```

Response (MCTP + SPDM):
```
05 10 04 00 00 00 04 10 00 11 00 12 00 13 00
```

Breakdown of Response:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `04`: RequestResponseCode (VERSION)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `04`: VersionNumberEntryCount (4 versions supported)
- `10 00`: SPDM version 1.0 in little-endian format
- `11 00`: SPDM version 1.1 in little-endian format
- `12 00`: SPDM version 1.2 in little-endian format
- `13 00`: SPDM version 1.3 in little-endian format

**Example 3: GET_VERSION with UNEXPECTED_REQUEST Error Response**

Request (MCTP + SPDM):
```
05 10 84 00 00
```

Response (MCTP + SPDM):
```
05 10 7F 03 00
```

Breakdown of Response:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `7F`: RequestResponseCode (ERROR)
- `03`: Error code (UNEXPECTED_REQUEST)
- `00`: Error data

**Example 4: GET_VERSION with RESPONSE_NOT_READY Error Response**

Request (MCTP + SPDM):
```
05 10 84 00 00
```

Response (MCTP + SPDM):
```
05 10 7F 07 00 10 84 00 00 00
```

Breakdown of Response:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `7F`: RequestResponseCode (ERROR)
- `07`: Error code (RESPONSE_NOT_READY)
- `00`: Extended Error Data
- `10`: Request SPDMVersion
- `84`: Request RequestResponseCode (GET_VERSION)
- `00 00 00`: Additional error data

**Example 5: GET_VERSION with Alpha Version Response**

Request (MCTP + SPDM):
```
05 10 84 00 00
```

Response (MCTP + SPDM):
```
05 10 04 00 00 00 02 10 00 13 01
```

Breakdown of Response:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `04`: RequestResponseCode (VERSION)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `02`: VersionNumberEntryCount (2 versions supported)
- `10 00`: SPDM version 1.0 in little-endian format
- `13 01`: SPDM version 1.3.0.1 (Alpha version 1 of SPDM 1.3) in little-endian format

**Example 6: GET_VERSION with Update Version Response**

Request (MCTP + SPDM):
```
05 10 84 00 00
```

Response (MCTP + SPDM):
```
05 10 04 00 00 00 02 10 00 12 10
```

Breakdown of Response:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `04`: RequestResponseCode (VERSION)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `02`: VersionNumberEntryCount (2 versions supported)
- `10 00`: SPDM version 1.0 in little-endian format
- `12 10`: SPDM version 1.2.1.0 (Update version 1 of SPDM 1.2) in little-endian format

**Example 7: GET_VERSION with UNSUPPORTED_REQUEST Error Response**

Request (MCTP + SPDM):
```
05 10 84 00 00
```

Response (MCTP + SPDM):
```
05 10 7F 05 00
```

Breakdown of Response:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `7F`: RequestResponseCode (ERROR)
- `05`: Error code (UNSUPPORTED_REQUEST)
- `00`: Error data

**Example 8: Raw GET_VERSION Request and Response (without MCTP encapsulation)**

Raw Request (SPDM only):
```
10 84 00 00
```

Breakdown of Raw Request:
- `10`: SPDMVersion (SPDM 1.0)
- `84`: RequestResponseCode (GET_VERSION)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)

Raw Response (SPDM only):
```
10 04 00 00 00 03 10 00 11 00 12 00
```

Breakdown of Raw Response:
- `10`: SPDMVersion (SPDM 1.0)
- `04`: RequestResponseCode (VERSION)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `03`: VersionNumberEntryCount (3 versions supported)
- `10 00`: SPDM version 1.0 in little-endian format
- `11 00`: SPDM version 1.1 in little-endian format
- `12 00`: SPDM version 1.2 in little-endian format

## GET_CAPABILITIES Command

The GET_CAPABILITIES command is the second message in the SPDM protocol flow and is used to discover and negotiate the capabilities supported by both the Requester and Responder. This command must be sent after GET_VERSION and before any other SPDM commands.

### Purpose and Functionality

The GET_CAPABILITIES command serves several critical purposes in the SPDM protocol:

1. **Capability Discovery**: Determines which SPDM features are supported by both parties
2. **Feature Negotiation**: Enables the Requester and Responder to agree on which features to use
3. **Parameter Exchange**: Communicates timing parameters and message size limitations
4. **Protocol Configuration**: Sets up the parameters for subsequent communication
5. **Security Feature Selection**: Identifies which security mechanisms will be available

### Message Format

#### GET_CAPABILITIES Request

The GET_CAPABILITIES request format as defined in the SPDM specification:

```
+----------------+----------------+----------------+----------------+----------------+----------------+----------------+
| SPDMVersion    | RequestResponseCode | Param1 (0x00)  | Param2 (0x00)  | Reserved       | CTExponent     | Reserved       |
+----------------+----------------+----------------+----------------+----------------+----------------+----------------+
| Flags          | DataTransferSize | MaxSPDMmsgSize |
+----------------+----------------+----------------+
```

Detailed field breakdown:

| Byte offset | Field | Size (bytes) | Value | Description |
|------------|-------|--------------|-------|-------------|
| 0 | SPDMVersion | 1 | Varies | Shall be the SPDMVersion as described in SPDM version |
| 1 | RequestResponseCode | 1 | 0xE1 | GET_CAPABILITIES. See Table 4 — SPDM request codes |
| 2 | Param1 | 1 | 0x00 | Reserved |
| 3 | Param2 | 1 | 0x00 | Reserved |
| 4 | Reserved | 1 | 0x00 | Reserved |
| 5 | CTExponent | 1 | 0-32 | Exponent of base 2, used to calculate CT. The equation for CT shall be 2^CTExponent microseconds (μs). For example, if CTExponent is 10, CT is 2^10 = 1024 μs |
| 6 | Reserved | 2 | 0x0000 | Reserved |
| 8 | Flags | 4 | Varies | Bitmap of supported capabilities. See Table 11 — Flag fields definitions for the Requester |
| 12 | DataTransferSize | 4 | ≥MinDataTransferSize | Maximum buffer size, in bytes, for receiving a single and complete SPDM message. The value shall be equal to or greater than MinDataTransferSize. The DataTransferSize excludes transport headers, encryption headers, and MAC |
| 16 | MaxSPDMmsgSize | 4 | ≥DataTransferSize | Maximum size, in bytes, of the internal buffer used to reassemble a single and complete Large SPDM message. This field shall be greater than or equal to DataTransferSize |

**Important Notes**:
- The SPDMVersion field shall match the negotiated SPDM version from the GET_VERSION exchange
- The DataTransferSize field helps the sender know whether to use the Large SPDM message transfer mechanism
- If the Requester does not support the Large SPDM message transfer mechanism, MaxSPDMmsgSize shall be equal to DataTransferSize
- The MinDataTransferSize value depends on the SPDM version (typically 42 bytes for SPDM 1.2+)

#### CAPABILITIES Response

The CAPABILITIES response format as defined in the SPDM specification:

```
+----------------+----------------+----------------+----------------+----------------+----------------+----------------+
| SPDMVersion    | RequestResponseCode | Param1 (0x00)  | Param2 (0x00)  | Reserved       | CTExponent     | Reserved       |
+----------------+----------------+----------------+----------------+----------------+----------------+----------------+
| Flags          | DataTransferSize | MaxSPDMmsgSize |
+----------------+----------------+----------------+
```

Detailed field breakdown:

| Byte offset | Field | Size (bytes) | Value | Description |
|------------|-------|--------------|-------|-------------|
| 0 | SPDMVersion | 1 | Varies | Shall be the SPDMVersion as described in SPDM version |
| 1 | RequestResponseCode | 1 | 0x61 | CAPABILITIES. See Table 5 — SPDM response codes |
| 2 | Param1 | 1 | 0x00 | Reserved |
| 3 | Param2 | 1 | 0x00 | Reserved |
| 4 | Reserved | 1 | 0x00 | Reserved |
| 5 | CTExponent | 1 | 0-32 | Exponent of base 2, used to calculate CT. The equation for CT shall be 2^CTExponent microseconds (μs) |
| 6 | Reserved | 2 | 0x0000 | Reserved |
| 8 | Flags | 4 | Varies | Bitmap of supported capabilities. See Table 12 — Flag fields definitions for the Responder |
| 12 | DataTransferSize | 4 | ≥MinDataTransferSize | Maximum buffer size, in bytes, for receiving a single and complete SPDM message |
| 16 | MaxSPDMmsgSize | 4 | ≥DataTransferSize | Maximum size, in bytes, of the internal buffer used to reassemble a single and complete Large SPDM message |

### Capability Flags

The Flags field in both the request and response is a 32-bit bitmap that indicates supported capabilities. The meaning of each bit varies between the Requester and Responder.

#### Requester Capability Flags (GET_CAPABILITIES Request)

Table 11 — Flag fields definitions for the Requester:

| Byte offset | Bit offset | Field | Description |
|------------|------------|-------|-------------|
| 0 | 0 | Reserved | Reserved |
| 0 | 1 | CERT_CAP | If set, Requester shall support DIGESTS and CERTIFICATE response messages |
| 0 | 2 | CHAL_CAP | DEPRECATED: If set, Requester shall support CHALLENGE_AUTH response message |
| 0 | [5:3] | Reserved | Reserved |
| 0 | 6 | ENCRYPT_CAP | If set, Requester shall support message encryption in a secure session. If set, when the Requester chooses to start a secure session, the Requester shall send one of the Session-Secrets-Exchange request messages supported by the Responder |
| 0 | 7 | MAC_CAP | If set, Requester shall support message authentication in a secure session. If set, when the Requester chooses to start a secure session, the Requester shall send one of the Session-Secrets-Exchange request messages supported by the Responder. MAC_CAP is not the same as the HMAC in the RequesterVerifyData or ResponderVerifyData fields of Session-Secrets-Exchange and Session-Secrets-Finish messages |
| 1 | 0 | MUT_AUTH_CAP | If set, Requester shall support mutual authentication |
| 1 | 1 | KEY_EX_CAP | If set, Requester shall support KEY_EXCHANGE request message. If set, ENCRYPT_CAP or MAC_CAP shall be set |
| 1 | [3:2] | PSK_CAP | Pre-shared key capabilities of the Requester.<br>• 00b: Requester shall not support pre-shared key capabilities<br>• 01b: Requester shall support pre-shared key capabilities<br>• 10b and 11b: Reserved<br>If supported, ENCRYPT_CAP or MAC_CAP shall be set |
| 1 | 4 | ENCAP_CAP | If set, Requester shall support GET_ENCAPSULATED_REQUEST, ENCAPSULATED_REQUEST, DELIVER_ENCAPSULATED_RESPONSE, and ENCAPSULATED_RESPONSE_ACK messages. Additionally, the transport may require the Requester to support these messages. ENCAP_CAP was previously deprecated because Basic mutual authentication is deprecated. Deprecation is removed since other messages may require ENCAP_CAP such as KEY_UPDATE which does not require mutual authentication |
| 1 | 5 | HBEAT_CAP | If set, Requester shall support HEARTBEAT messages |
| 1 | 6 | KEY_UPD_CAP | If set, Requester shall support KEY_UPDATE messages |
| 1 | 7 | HANDSHAKE_IN_THE_CLEAR_CAP | If set, the Requester can support a Responder that can only send and receive all SPDM messages exchanged during the Session Handshake Phase in the clear (such as without encryption and message authentication). Application data is encrypted and/or authenticated using the negotiated cryptographic algorithms as normal. Setting this bit leads to changes in the contents of certain SPDM messages, discussed in other parts of this specification.<br>If this bit is cleared, the Requester signals that it requires encryption and/or message authentication of SPDM messages exchanged during the Session Handshake Phase.<br>If the Requester does not support encryption and message authentication, then this bit shall be zero.<br>In other words, this bit indicates whether MAC_CAP and ENCRYPT_CAP is involved accordingly in the handshake phase of a secure session or both encryption and message authentication capabilities are disabled in the session handshake phase of a secure session |
| 2 | 0 | PUB_KEY_ID_CAP | If set, the public key of the Requester was provisioned to the Responder. The transport layer is responsible for identifying the Responder. In this case, the CERT_CAP of the Requester shall be 0 |
| 2 | 1 | CHUNK_CAP | If set, Requester shall support Large SPDM message transfer mechanism messages |
| 2 | [7:2] | Reserved | Reserved |
| 3 | [7:0] | Reserved | Reserved |

**Bit-to-Value Mapping**:

| Flag Bit | Value | SPDM Version | Name |
|----------|-------|--------------|------|
| 1 | 0x00000002 | 1.1+ | CERT_CAP |
| 2 | 0x00000004 | 1.1+ | CHAL_CAP (DEPRECATED) |
| 6 | 0x00000040 | 1.1+ | ENCRYPT_CAP |
| 7 | 0x00000080 | 1.1+ | MAC_CAP |
| 8 | 0x00000100 | 1.1+ | MUT_AUTH_CAP |
| 9 | 0x00000200 | 1.1+ | KEY_EX_CAP |
| 10 | 0x00000400 | 1.1+ | PSK_CAP (01b) |
| 12 | 0x00001000 | 1.1+ | ENCAP_CAP |
| 13 | 0x00002000 | 1.1+ | HBEAT_CAP |
| 14 | 0x00004000 | 1.1+ | KEY_UPD_CAP |
| 15 | 0x00008000 | 1.2+ | HANDSHAKE_IN_THE_CLEAR_CAP |
| 16 | 0x00010000 | 1.2+ | PUB_KEY_ID_CAP |
| 17 | 0x00020000 | 1.2+ | CHUNK_CAP |
| 22 | 0x00400000 | 1.3+ | EP_INFO_CAP (Without signature) |
| 23 | 0x00800000 | 1.3+ | EP_INFO_CAP (With signature) |
| 25 | 0x02000000 | 1.3+ | EVENT_CAP |
| 26 | 0x04000000 | 1.3+ | MULTI_KEY_CAP (Only mode) |
| 27 | 0x08000000 | 1.3+ | MULTI_KEY_CAP (Negotiation mode) |

#### Responder Capability Flags (CAPABILITIES Response)

Table 12 — Flag fields definitions for the Responder:

| Byte offset | Bit offset | Field | Description |
|------------|------------|-------|-------------|
| 0 | 0 | CACHE_CAP | If set, the Responder shall support the ability to cache the Negotiated State across a Reset. This allows the Requester to skip reissuing the GET_VERSION, GET_CAPABILITIES and NEGOTIATE_ALGORITHMS requests after a Reset. The Responder shall cache the selected cryptographic algorithms as one of the parameters of the Negotiated State. If the Requester chooses to skip issuing these requests after the Reset, the Requester shall also cache the same selected cryptographic algorithms |
| 0 | 1 | CERT_CAP | If set, Responder shall support DIGESTS and CERTIFICATE response messages |
| 0 | 2 | CHAL_CAP | If set, Responder shall support CHALLENGE_AUTH response message |
| 0 | [4:3] | MEAS_CAP | MEASUREMENTS response capabilities of the Responder.<br>• 00b: The Responder shall not support MEASUREMENTS response capabilities<br>• 01b: The Responder shall support MEASUREMENTS response but cannot perform signature generation<br>• 10b: The Responder shall support MEASUREMENTS response and can generate signatures<br>• 11b: Reserved<br>Note that, apart from affecting MEASUREMENTS, this capability also affects Param2 of CHALLENGE, Param1 of KEY_EXCHANGE, Param1 of PSK_EXCHANGE, MeasurementSummaryHash field of KEY_EXCHANGE_RSP, CHALLENGE_AUTH, PSK_EXCHANGE_RSP. See the respective request and response clauses for further details |
| 0 | 5 | MEAS_FRESH_CAP | 0: As part of MEASUREMENTS response message, the Responder may return MEASUREMENTS that were computed during the last Responder's Reset<br>1: The Responder shall support recomputing all MEASUREMENTS without requiring a Reset, and shall always return fresh MEASUREMENTS as part of MEASUREMENTS response message |
| 0 | 6 | ENCRYPT_CAP | If set, Responder shall support message encryption in a secure session. If set, PSK_CAP or KEY_EX_CAP shall be set accordingly to indicate support |
| 0 | 7 | MAC_CAP | If set, Responder shall support message authentication in a secure session. If set, PSK_CAP or KEY_EX_CAP shall be set accordingly to indicate support. MAC_CAP is not the same as the HMAC in the RequesterVerifyData or ResponderVerifyData fields of Session-Secrets-Exchange and Session-Secrets-Finish messages |
| 1 | 0 | MUT_AUTH_CAP | If set, Responder shall support mutual authentication |
| 1 | 1 | KEY_EX_CAP | If set, Responder shall support KEY_EXCHANGE_RSP response message. If set, ENCRYPT_CAP or MAC_CAP shall be set |
| 1 | [3:2] | PSK_CAP | Pre-Shared Key capabilities of the Responder.<br>• 00b: Responder shall not support Pre-Shared Key capabilities<br>• 01b: Responder shall support Pre-Shared Key without ResponderContext for session key derivation<br>• 10b: Responder shall support Pre-Shared Key with ResponderContext for session key derivation<br>• 11b: Reserved<br>If supported, ENCRYPT_CAP or MAC_CAP shall be set |
| 1 | 4 | ENCAP_CAP | If set, Responder shall support GET_ENCAPSULATED_REQUEST, ENCAPSULATED_REQUEST, DELIVER_ENCAPSULATED_RESPONSE, and ENCAPSULATED_RESPONSE_ACK messages. Additionally, the transport may require the Responder to support these messages. ENCAP_CAP was previously deprecated because Basic mutual authentication is deprecated. Deprecation is removed since other messages may require ENCAP_CAP such as KEY_UPDATE which does not require mutual authentication |
| 1 | 5 | HBEAT_CAP | If set, Responder shall support HEARTBEAT messages |
| 1 | 6 | KEY_UPD_CAP | If set, Responder shall support KEY_UPDATE messages |
| 1 | 7 | HANDSHAKE_IN_THE_CLEAR_CAP | If set, the Responder can only send and receive messages without encryption and message authentication during the Session Handshake Phase. If set, KEY_EX_CAP shall also be set. Setting this bit leads to changes in the contents of certain SPDM messages, discussed in other parts of this specification.<br>If the Responder does not support encryption and message authentication, then this bit shall be zero.<br>In other words, this bit indicates whether MAC_CAP and ENCRYPT_CAP is involved accordingly in the handshake phase of a secure session or both encryption and message authentication capabilities are disabled in the session handshake phase of a secure session |
| 2 | 0 | PUB_KEY_ID_CAP | If set, the public key of the Responder was provisioned to the Requester. The transport layer is responsible for identifying the Requester. In this case, CERT_CAP and ALIAS_CERT_CAP of the Responder shall both be 0 |
| 2 | 1 | CHUNK_CAP | If set, Responder shall support Large SPDM message transfer mechanism messages |
| 2 | 2 | ALIAS_CERT_CAP | If set, the Responder uses the AliasCert model. See Identity provisioning for details |
| 2 | 3 | SET_CERT_CAP | If set, Responder shall support SET_CERTIFICATE_RSP response messages |
| 2 | 4 | CSR_CAP | If set, Responder shall support CSR response messages. If this bit is set SET_CERT_CAP shall be set |
| 2 | 5 | CERT_INSTALL_RESET_CAP | If set, Responder may return an ERROR message with ErrorCode = ResetRequired to complete a certificate provisioning request. If this bit is set, CSR_CAP and/or SET_CERT_CAP shall be set |
| 2 | [7:6] | Reserved | Reserved |
| 3 | [7:0] | Reserved | Reserved |

**Bit-to-Value Mapping**:

| Flag Bit | Value | SPDM Version | Name |
|----------|-------|--------------|------|
| 0 | 0x00000001 | 1.0+ | CACHE_CAP |
| 1 | 0x00000002 | 1.0+ | CERT_CAP |
| 2 | 0x00000004 | 1.0+ | CHAL_CAP |
| 3 | 0x00000008 | 1.0+ | MEAS_CAP (Without signature) |
| 4 | 0x00000010 | 1.0+ | MEAS_CAP (With signature) |
| 5 | 0x00000020 | 1.0+ | MEAS_FRESH_CAP |
| 6 | 0x00000040 | 1.1+ | ENCRYPT_CAP |
| 7 | 0x00000080 | 1.1+ | MAC_CAP |
| 8 | 0x00000100 | 1.1+ | MUT_AUTH_CAP |
| 9 | 0x00000200 | 1.1+ | KEY_EX_CAP |
| 10 | 0x00000400 | 1.1+ | PSK_CAP (Without context) |
| 11 | 0x00000800 | 1.1+ | PSK_CAP (With context) |
| 12 | 0x00001000 | 1.1+ | ENCAP_CAP |
| 13 | 0x00002000 | 1.1+ | HBEAT_CAP |
| 14 | 0x00004000 | 1.1+ | KEY_UPD_CAP |
| 15 | 0x00008000 | 1.2+ | HANDSHAKE_IN_THE_CLEAR_CAP |
| 16 | 0x00010000 | 1.2+ | PUB_KEY_ID_CAP |
| 17 | 0x00020000 | 1.2+ | CHUNK_CAP |
| 18 | 0x00040000 | 1.2+ | ALIAS_CERT_CAP |
| 19 | 0x00080000 | 1.2+ | SET_CERT_CAP |
| 20 | 0x00100000 | 1.2+ | CSR_CAP |
| 21 | 0x00200000 | 1.2+ | CERT_INSTALL_RESET_CAP |
| 22 | 0x00400000 | 1.3+ | EP_INFO_CAP (Without signature) |
| 23 | 0x00800000 | 1.3+ | EP_INFO_CAP (With signature) |
| 24 | 0x01000000 | 1.3+ | MEL_CAP |
| 25 | 0x02000000 | 1.3+ | EVENT_CAP |
| 26 | 0x04000000 | 1.3+ | MULTI_KEY_CAP (Only mode) |
| 27 | 0x08000000 | 1.3+ | MULTI_KEY_CAP (Negotiation mode) |
| 28 | 0x10000000 | 1.3+ | GET_KEY_PAIR_INFO_CAP |

### Protocol Flow

1. **Requester Action**:
   - The Requester constructs a GET_CAPABILITIES request message
   - The Requester includes its supported capabilities in the Flags field
   - The Requester sends the GET_CAPABILITIES request to the Responder
   - The Requester waits for a CAPABILITIES response

2. **Responder Action**:
   - The Responder receives the GET_CAPABILITIES request
   - The Responder validates the request format
   - The Responder records the Requester's capabilities
   - The Responder constructs a CAPABILITIES response with its supported capabilities
   - The Responder sends the CAPABILITIES response to the Requester

3. **Capability Negotiation**:
   - The Requester receives the CAPABILITIES response
   - The Requester validates the response format
   - The Requester records the Responder's capabilities
   - The Requester determines which features can be used based on mutual support

### State Management

The GET_CAPABILITIES command has significant effects on the SPDM state machine:

1. **State Verification**:
   - The Responder verifies that GET_VERSION has been completed successfully
   - If not, the Responder returns an UNEXPECTED_REQUEST error

2. **Capability Recording**:
   - Both parties record each other's capabilities for future reference
   - The CT_Exponent values are stored for calculating timeout values
   - The DataTransSize and MaxSPDMmsgSize values are stored for message size limits

3. **Connection State**:
   - After successful capability exchange, the connection state is set to NEGOTIATED_CAPABILITIES
   - This allows the protocol to proceed to algorithm negotiation

4. **Transcript Management**:
   - The GET_CAPABILITIES request and CAPABILITIES response are added to the transcript buffer A
   - This transcript is used for subsequent message authentication

### Error Handling

The GET_CAPABILITIES command can encounter several error conditions:

1. **Invalid State**:
   - If GET_VERSION has not been completed successfully
   - Response: ERROR with code UNEXPECTED_REQUEST (0x03)

2. **Invalid Request Format**:
   - If the request size is incorrect for the SPDM version
   - If the request contains invalid parameters
   - Response: ERROR with code INVALID_REQUEST (0x01)

3. **Invalid CT_Exponent**:
   - If the CT_Exponent value exceeds the maximum allowed value (32)
   - Response: ERROR with code INVALID_REQUEST (0x01)

4. **Invalid DataTransSize**:
   - If DataTransSize is less than the minimum required (42 bytes in SPDM 1.2+)
   - If DataTransSize is greater than MaxSPDMmsgSize
   - Response: ERROR with code INVALID_REQUEST (0x01)

5. **Inconsistent Flags**:
   - If the flags indicate incompatible capability combinations
   - Response: ERROR with code INVALID_REQUEST (0x01)

6. **Busy State**:
   - If the Responder is temporarily unable to process the request
   - Response: ERROR with code BUSY (0x02)
   - The Requester should retry after a delay

### Retry Behavior

When the Requester receives an error response to a GET_CAPABILITIES request, it should follow these retry procedures:

1. **BUSY Error**:
   - Wait for the specified time (2^CT_Exponent μs) if provided
   - Retry the GET_CAPABILITIES request
   - Continue retrying until successful or retry limit is reached

2. **REQUEST_RESYNCH Error**:
   - Reset the local context
   - Restart the SPDM communication with GET_VERSION

3. **Other Errors**:
   - Terminate the SPDM communication
   - Report the error to higher layers

### Implementation Considerations

1. **CT_Exponent Selection**:
   - The CT_Exponent should be chosen based on the device's processing capabilities
   - Smaller values reduce latency but may cause BUSY errors if the Responder cannot respond quickly enough
   - Larger values increase latency but reduce the likelihood of BUSY errors

2. **Capability Flag Consistency**:
   - Implementations must ensure that capability flags are consistent
   - For example, if KEY_EX_CAP is set, either ENCRYPT_CAP or MAC_CAP must also be set
   - If PSK_CAP is set, either ENCRYPT_CAP or MAC_CAP must also be set

3. **Version Compatibility**:
   - Implementations must adjust the request and response formats based on the negotiated SPDM version
   - Fields not defined in earlier versions must be omitted

4. **Security Implications**:
   - The GET_CAPABILITIES exchange is not authenticated
   - Attackers could potentially downgrade security features
   - Later authentication steps help mitigate this risk

5. **Message Size Limits**:
   - In SPDM 1.2+, implementations must respect the DataTransSize and MaxSPDMmsgSize limits
   - Messages exceeding these limits must be chunked if chunking is supported

### GET_CAPABILITIES Examples

#### SPDM 1.1 Example

**Request (MCTP + SPDM)**:
```
05 11 E1 00 00 00 0A 00 00 00 00 03 E4
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `11`: SPDMVersion (SPDM 1.1)
- `E1`: RequestResponseCode (GET_CAPABILITIES)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `0A`: CTExponent (10)
- `00 00`: Reserved bytes
- `00 00 03 E4`: Flags (0x000003E4) indicating support for:
  - CERT_CAP (0x2)
  - CHAL_CAP (0x4)
  - ENCRYPT_CAP (0x40)
  - MAC_CAP (0x80)
  - KEY_EX_CAP (0x200)
  - PSK_CAP_REQUESTER (0x400)

**Response (MCTP + SPDM)**:
```
05 11 61 00 00 00 0C 00 00 00 00 03 F7
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `11`: SPDMVersion (SPDM 1.1)
- `61`: RequestResponseCode (CAPABILITIES)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `0C`: CTExponent (12)
- `00 00`: Reserved bytes
- `00 00 03 F7`: Flags (0x000003F7) indicating support for:
  - CACHE_CAP (0x1)
  - CERT_CAP (0x2)
  - CHAL_CAP (0x4)
  - MEAS_CAP_SIG (0x10)
  - MEAS_FRESH_CAP (0x20)
  - ENCRYPT_CAP (0x40)
  - MAC_CAP (0x80)
  - KEY_EX_CAP (0x200)
  - PSK_CAP_RESPONDER (0x400)

#### SPDM 1.2 Example

**Request (MCTP + SPDM)**:
```
05 12 E1 00 00 00 0A 00 00 00 00 03 E4 00 00 10 00 00 00 20 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `12`: SPDMVersion (SPDM 1.2)
- `E1`: RequestResponseCode (GET_CAPABILITIES)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `0A`: CTExponent (10)
- `00 00`: Reserved bytes
- `00 00 03 E4`: Flags (0x000003E4)
- `00 00 10 00`: DataTransferSize (4096 bytes)
- `00 00 20 00`: MaxSPDMmsgSize (8192 bytes)

**Response (MCTP + SPDM)**:
```
05 12 61 00 00 00 0C 00 00 00 00 03 F7 00 00 08 00 00 00 10 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `12`: SPDMVersion (SPDM 1.2)
- `61`: RequestResponseCode (CAPABILITIES)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `0C`: CTExponent (12)
- `00 00`: Reserved bytes
- `00 00 03 F7`: Flags (0x000003F7)
- `00 00 08 00`: DataTransferSize (2048 bytes)
- `00 00 10 00`: MaxSPDMmsgSize (4096 bytes)

#### Error Response Example

**UNEXPECTED_REQUEST Error Response (MCTP + SPDM)**:
```
05 10 7F 03 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `7F`: RequestResponseCode (ERROR)
- `03`: Error code (UNEXPECTED_REQUEST)
- `00`: Error data

**INVALID_REQUEST Error Response (MCTP + SPDM)**:
```
05 10 7F 01 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `7F`: RequestResponseCode (ERROR)
- `01`: Error code (INVALID_REQUEST)
- `00`: Error data

**Raw GET_CAPABILITIES Example (without MCTP encapsulation)**

Raw Request (SPDM only):
```
12 E1 00 00 00 0A 00 00 00 00 03 E4 00 00 10 00 00 00 20 00
```

Breakdown of Raw Request:
- `12`: SPDMVersion (SPDM 1.2)
- `E1`: RequestResponseCode (GET_CAPABILITIES)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `0A`: CTExponent (10)
- `00 00`: Reserved bytes
- `00 00 03 E4`: Flags (0x000003E4)
- `00 00 10 00`: DataTransferSize (4096 bytes)
- `00 00 20 00`: MaxSPDMmsgSize (8192 bytes)

Raw Response (SPDM only):
```
12 61 00 00 00 0C 00 00 00 00 03 F7 00 00 08 00 00 00 10 00
```

Breakdown of Raw Response:
- `12`: SPDMVersion (SPDM 1.2)
- `61`: RequestResponseCode (CAPABILITIES)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `0C`: CTExponent (12)
- `00 00`: Reserved bytes
- `00 00 03 F7`: Flags (0x000003F7)
- `00 00 08 00`: DataTransferSize (2048 bytes)
- `00 00 10 00`: MaxSPDMmsgSize (4096 bytes)

#### Additional GET_CAPABILITIES Examples

**Example 1: SPDM 1.3 GET_CAPABILITIES with Minimal Capabilities**

Request (MCTP + SPDM):
```
05 13 E1 00 00 00 0A 00 00 00 00 00 42 00 00 00 2A 00 00 00 2A
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `13`: SPDMVersion (SPDM 1.3)
- `E1`: RequestResponseCode (GET_CAPABILITIES)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `0A`: CTExponent (10)
- `00 00`: Reserved bytes
- `00 00 00 42`: Flags (0x00000042) indicating support for:
  - CERT_CAP (0x2)
  - ENCRYPT_CAP (0x40)
- `00 00 00 2A`: DataTransferSize (42 bytes, minimum required size)
- `00 00 00 2A`: MaxSPDMmsgSize (42 bytes, same as DataTransferSize)

Response (MCTP + SPDM):
```
05 13 61 00 00 00 0C 00 00 00 00 00 27 00 00 00 2A 00 00 00 2A
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `13`: SPDMVersion (SPDM 1.3)
- `61`: RequestResponseCode (CAPABILITIES)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `0C`: CTExponent (12)
- `00 00`: Reserved bytes
- `00 00 00 27`: Flags (0x00000027) indicating support for:
  - CACHE_CAP (0x1)
  - CERT_CAP (0x2)
  - CHAL_CAP (0x4)
  - MEAS_FRESH_CAP (0x20)
- `00 00 00 2A`: DataTransferSize (42 bytes)
- `00 00 00 2A`: MaxSPDMmsgSize (42 bytes)

**Example 2: GET_CAPABILITIES with Extensive Capabilities**

Request (MCTP + SPDM):
```
05 12 E1 00 00 00 0A 00 00 00 00 3F FC 00 01 00 00 00 02 00 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `12`: SPDMVersion (SPDM 1.2)
- `E1`: RequestResponseCode (GET_CAPABILITIES)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `0A`: CTExponent (10)
- `00 00`: Reserved bytes
- `00 00 3F FC`: Flags (0x00003FFC) indicating support for:
  - CERT_CAP (0x2)
  - CHAL_CAP (0x4)
  - ENCRYPT_CAP (0x40)
  - MAC_CAP (0x80)
  - MUT_AUTH_CAP (0x100)
  - KEY_EX_CAP (0x200)
  - PSK_CAP (0x400)
  - ENCAP_CAP (0x1000)
  - HBEAT_CAP (0x2000)
  - KEY_UPD_CAP (0x4000)
  - HANDSHAKE_IN_THE_CLEAR_CAP (0x8000)
  - PUB_KEY_ID_CAP (0x10000)
  - CHUNK_CAP (0x20000)
- `00 01 00 00`: DataTransferSize (65536 bytes)
- `00 02 00 00`: MaxSPDMmsgSize (131072 bytes)

Response (MCTP + SPDM):
```
05 12 61 00 00 00 0C 00 00 00 00 3F F7 00 00 80 00 00 01 00 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `12`: SPDMVersion (SPDM 1.2)
- `61`: RequestResponseCode (CAPABILITIES)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00`: Reserved byte
- `0C`: CTExponent (12)
- `00 00`: Reserved bytes
- `00 00 3F F7`: Flags (0x00003FF7) indicating support for:
  - CACHE_CAP (0x1)
  - CERT_CAP (0x2)
  - CHAL_CAP (0x4)
  - MEAS_CAP (0x10) - With signature
  - MEAS_FRESH_CAP (0x20)
  - ENCRYPT_CAP (0x40)
  - MAC_CAP (0x80)
  - MUT_AUTH_CAP (0x100)
  - KEY_EX_CAP (0x200)
  - PSK_CAP (0x400)
  - ENCAP_CAP (0x1000)
  - HBEAT_CAP (0x2000)
  - KEY_UPD_CAP (0x4000)
  - HANDSHAKE_IN_THE_CLEAR_CAP (0x8000)
  - PUB_KEY_ID_CAP (0x10000)
  - CHUNK_CAP (0x20000)
- `00 00 80 00`: DataTransferSize (32768 bytes)
- `00 01 00 00`: MaxSPDMmsgSize (65536 bytes)

**Example 3: GET_CAPABILITIES with BUSY Error and Retry**

Request (MCTP + SPDM):
```
05 11 E1 00 00 00 0A 00 00 00 00 03 E4
```

Response (MCTP + SPDM) - First attempt:
```
05 10 7F 02 03
```

Breakdown of Error Response:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `7F`: RequestResponseCode (ERROR)
- `02`: Error code (BUSY)
- `03`: Error data (Retry after 2^3 = 8 microseconds)

Request (MCTP + SPDM) - Retry after delay:
```
05 11 E1 00 00 00 0A 00 00 00 00 03 E4
```

Response (MCTP + SPDM) - After retry:
```
05 11 61 00 00 00 0C 00 00 00 00 03 F7
```

**Example 4: GET_CAPABILITIES with RESPONSE_NOT_READY Error**

Request (MCTP + SPDM):
```
05 12 E1 00 00 00 0A 00 00 00 00 03 E4 00 00 10 00 00 00 20 00
```

Response (MCTP + SPDM):
```
05 12 7F 07 00 12 E1 00 00 00 0A 00 00 00 00 03 E4 00 00 10 00 00 00 20 00
```

Breakdown of Error Response:
- `05`: MCTP header (message type 0x05 for SPDM)
- `12`: SPDMVersion (SPDM 1.2)
- `7F`: RequestResponseCode (ERROR)
- `07`: Error code (RESPONSE_NOT_READY)
- `00`: Extended Error Data
- `12`: Request SPDMVersion
- `E1`: Request RequestResponseCode (GET_CAPABILITIES)
- Remaining bytes: Original request parameters

**Example 5: SPDM 1.0 GET_CAPABILITIES (Simplified Format)**

Request (MCTP + SPDM):
```
05 10 E1 00 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `E1`: RequestResponseCode (GET_CAPABILITIES)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)

Response (MCTP + SPDM):
```
05 10 61 00 00 00 00 00 37
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `61`: RequestResponseCode (CAPABILITIES)
- `00`: Param1 (Reserved)
- `00`: Param2 (Reserved)
- `00 00 00 37`: Flags (0x00000037) indicating support for:
  - CACHE_CAP (0x1)
  - CERT_CAP (0x2)
  - CHAL_CAP (0x4)
  - MEAS_CAP (0x10) - With signature
  - MEAS_FRESH_CAP (0x20)

## NEGOTIATE_ALGORITHMS Command

The NEGOTIATE_ALGORITHMS command is the third message in the SPDM protocol flow and is used to negotiate the cryptographic algorithms that will be used for subsequent operations. This command must be sent after GET_CAPABILITIES and before any authentication or session establishment commands.

### Purpose and Functionality

The NEGOTIATE_ALGORITHMS command serves several critical purposes in the SPDM protocol:

1. **Algorithm Discovery**: Determines which cryptographic algorithms are supported by both parties
2. **Algorithm Selection**: Enables the Requester and Responder to agree on which algorithms to use
3. **Security Level Negotiation**: Establishes the security strength of the connection
4. **Measurement Specification**: Determines how firmware measurements will be represented
5. **Cryptographic Suite Configuration**: Sets up the complete cryptographic environment for the session

### Message Format

#### NEGOTIATE_ALGORITHMS Request

Table 13 — NEGOTIATE_ALGORITHMS request message format:

```
+----------------+----------------+----------------+----------------+----------------+----------------+
| SPDMVersion    | RequestResponseCode | Param1        | Param2 (0x00)  | Length         | MeasurementSpecification |
+----------------+----------------+----------------+----------------+----------------+----------------+
| OtherParamsSupport | BaseAsymAlgo  | BaseHashAlgo   | Reserved       | ExtAsymCount   | ExtHashCount   |
+----------------+----------------+----------------+----------------+----------------+----------------+
| Reserved       | ExtAsym[A]     | ExtHash[E]     | ReqAlgStruct   |
+----------------+----------------+----------------+----------------+
```

Detailed field breakdown:

| Byte offset | Field | Size (bytes) | Value | Description |
|------------|-------|--------------|-------|-------------|
| 0 | SPDMVersion | 1 | Varies | Shall be the SPDMVersion as described in SPDM version |
| 1 | RequestResponseCode | 1 | 0xE3 | NEGOTIATE_ALGORITHMS. See Table 4 — SPDM request codes |
| 2 | Param1 | 1 | Varies | Number of algorithms structure tables in this request using ReqAlgStruct |
| 3 | Param2 | 1 | 0x00 | Reserved |
| 4 | Length | 2 | Varies | Length of the entire request message, in bytes. Length shall be less than or equal to 128 bytes |
| 6 | MeasurementSpecification | 1 | Varies | Bit mask. The measurement specification is used in the MEASUREMENTS response. The Requester can set zero or one bit to indicate the measurement specification support.<br>• Bit 0: This bit shall indicate support for the DMTF-defined measurement specification. See Table 43 — DMTF measurement specification format |
| 7 | OtherParamsSupport | 1 | Varies | Selection Bit mask.<br>Bits [3:0] - See Opaque Data Format Support and Selection Table<br>Bits [7:4] - Reserved |
| 8 | BaseAsymAlgo | 4 | Varies | Bit mask listing Requester-supported SPDM-enumerated asymmetric key signature algorithms for the purpose of signature verification. If the capabilities do not support this algorithm, this value is not used and shall be set to zero. Let SigLen be the size of the signature in bytes.<br>• Byte 0 Bit 0: TPM_ALG_RSASSA_2048 where SigLen=256<br>• Byte 0 Bit 1: TPM_ALG_RSAPSS_2048 where SigLen=256<br>• Byte 0 Bit 2: TPM_ALG_RSASSA_3072 where SigLen=384<br>• Byte 0 Bit 3: TPM_ALG_RSAPSS_3072 where SigLen=384<br>• Byte 0 Bit 4: TPM_ALG_ECDSA_ECC_NIST_P256 where SigLen=64 (32-byte r followed by 32-byte s)<br>• Byte 0 Bit 5: TPM_ALG_RSASSA_4096 where SigLen=512<br>• Byte 0 Bit 6: TPM_ALG_RSAPSS_4096 where SigLen=512<br>• Byte 0 Bit 7: TPM_ALG_ECDSA_ECC_NIST_P384 where SigLen=96 (48-byte r followed by 48-byte s)<br>• Byte 1 Bit 0: TPM_ALG_ECDSA_ECC_NIST_P521 where SigLen=132 (66-byte r followed by 66-byte s)<br>• Byte 1 Bit 1: TPM_ALG_SM2_ECC_SM2_P256 where SigLen=64 (32-byte SM2_R followed by 32-byte SM2_S)<br>• Byte 1 Bit 2: EdDSA ed25519 where SigLen=64 (32-byte R followed by 32-byte S)<br>• Byte 1 Bit 3: EdDSA ed448 where SigLen=114 (57-byte R followed by 57-byte S)<br>• All other values reserved |
| 12 | BaseHashAlgo | 4 | Varies | Bit mask listing Requester-supported SPDM-enumerated cryptographic hashing algorithms. If the capabilities do not support this algorithm, this value is not used and shall be set to zero.<br>• Byte 0 Bit 0: TPM_ALG_SHA_256<br>• Byte 0 Bit 1: TPM_ALG_SHA_384<br>• Byte 0 Bit 2: TPM_ALG_SHA_512<br>• Byte 0 Bit 3: TPM_ALG_SHA3_256<br>• Byte 0 Bit 4: TPM_ALG_SHA3_384<br>• Byte 0 Bit 5: TPM_ALG_SHA3_512<br>• Byte 0 Bit 6: TPM_ALG_SM3_256<br>• All other values reserved |
| 16 | Reserved | 12 | 0x00 | Reserved |
| 28 | ExtAsymCount | 1 | A | Number of Requester-supported extended asymmetric key signature algorithms (=A) for the purpose of signature verification. A + E + ExtAlgCount2 + ExtAlgCount3 + ExtAlgCount4 + ExtAlgCount5 shall be less than or equal to 20. If the capabilities do not support this algorithm, this value is not used and shall be set to zero |
| 29 | ExtHashCount | 1 | E | Number of Requester-supported extended hashing algorithms (=E). A + E + ExtAlgCount2 + ExtAlgCount3 + ExtAlgCount4 + ExtAlgCount5 shall be less than or equal to 20. If the capabilities do not support this algorithm, this value is not used and shall be set to zero |
| 30 | Reserved | 2 | 0x0000 | Reserved |
| 32 | ExtAsym | 4 × A | Varies | List of Requester-supported extended asymmetric key signature algorithms for the purpose of signature verification. Table 25 — Extended Algorithm field format describes the format of this field |
| 32 + 4 × A | ExtHash | 4 × E | Varies | List of the extended hashing algorithms supported by Requester. Table 25 — Extended Algorithm field format describes the format of this field |
| 32 + 4 × A + 4 × E | ReqAlgStruct | AlgStructSize | Varies | See the AlgStructure request field |

**Table 14 — Algorithm request structure**:

| Byte offset | Field | Size (bytes) | Description |
|------------|-------|--------------|-------------|
| 0 | AlgType | 1 | Type of algorithm.<br>• 0 and 1: Reserved<br>• 2: DHE<br>• 3: AEADCipherSuite<br>• 4: ReqBaseAsymAlg<br>• 5: KeySchedule<br>• All other values reserved |
| 1 | AlgCount | 1 | Requester supported fixed algorithms.<br>• Bit [7:4]: Number of bytes required to describe Requester supported SPDM-enumerated fixed algorithms (= FixedAlgCount). FixedAlgCount + 2 shall be a multiple of 4<br>• Bit [3:0]: Number of Requester-supported extended algorithms (= ExtAlgCount) |
| 2 | AlgSupported | FixedAlgCount | Bit mask listing Requester-supported SPDM-enumerated algorithms |
| 2 + FixedAlgCount | AlgExternal | 4 × ExtAlgCount | List of Requester-supported extended algorithms. Table 25 — Extended Algorithm field format describes the format of this field |

**Table 15 — DHE structure**:

| Byte offset | Field | Size (bytes) | Description |
|------------|-------|--------------|-------------|
| 0 | AlgType | 1 | 0x02 = DHE |
| 1 | AlgCount | 1 | • Bit [7:4]: Shall be a value of 2<br>• Bit [3:0]: Number of Requester-supported extended DHE groups (= ExtAlgCount2) |
| 2 | AlgSupported | 2 | Bit mask listing Requester-supported SPDM-enumerated Diffie-Hellman Ephemeral (DHE) groups. Values in parentheses specify the size of the corresponding public values associated with each group.<br>• Byte 0 Bit 0: ffdhe2048 (D = 256)<br>• Byte 0 Bit 1: ffdhe3072 (D = 384)<br>• Byte 0 Bit 2: ffdhe4096 (D = 512)<br>• Byte 0 Bit 3: secp256r1 (D = 64, C = 32)<br>• Byte 0 Bit 4: secp384r1 (D = 96, C = 48)<br>• Byte 0 Bit 5: secp521r1 (D = 132, C = 66)<br>• Byte 0 Bit 6: SM2_P256 (Part 3 and Part 5 of GB/T 32918 specification) (D = 64, C = 32)<br>• All other values reserved |
| 4 | AlgExternal | 4 × ExtAlgCount2 | List of Requester-supported extended DHE groups. Table 25 — Extended Algorithm field format describes the format of this field |

#### ALGORITHMS Response

The ALGORITHMS response format follows a similar structure to the request format:

```
+----------------+----------------+----------------+----------------+----------------+----------------+
| SPDMVersion    | RequestResponseCode | Param1        | Param2 (0x00)  | Length         | MeasurementSpecificationSel |
+----------------+----------------+----------------+----------------+----------------+----------------+
| OtherParamsSelSupport | BaseAsymAlgoSel | BaseHashAlgoSel | Reserved       | ExtAsymSelCount | ExtHashSelCount |
+----------------+----------------+----------------+----------------+----------------+----------------+
| Reserved       | ExtAsymSel[A]  | ExtHashSel[E]  | AlgStructSel   |
+----------------+----------------+----------------+----------------+
```

Detailed field breakdown:

| Byte offset | Field | Size (bytes) | Value | Description |
|------------|-------|--------------|-------|-------------|
| 0 | SPDMVersion | 1 | Varies | Shall be the SPDMVersion as described in SPDM version |
| 1 | RequestResponseCode | 1 | 0x63 | ALGORITHMS. See Table 5 — SPDM response codes |
| 2 | Param1 | 1 | Varies | Number of algorithms structure tables in this response |
| 3 | Param2 | 1 | 0x00 | Reserved |
| 4 | Length | 2 | Varies | Length of the entire response message, in bytes |
| 6 | MeasurementSpecificationSel | 1 | Varies | Selected measurement specification |
| 7 | OtherParamsSelSupport | 1 | Varies | Selected other parameters<br>Bits [3:0] - Selected opaque data format<br>Bits [7:4] - Reserved |
| 8 | BaseAsymAlgoSel | 4 | Varies | Selected base asymmetric algorithm |
| 12 | BaseHashAlgoSel | 4 | Varies | Selected base hash algorithm |
| 16 | Reserved | 12 | 0x00 | Reserved |
| 28 | ExtAsymSelCount | 1 | A | Number of selected extended asymmetric key signature algorithms (=A) |
| 29 | ExtHashSelCount | 1 | E | Number of selected extended hashing algorithms (=E) |
| 30 | Reserved | 2 | 0x0000 | Reserved |
| 32 | ExtAsymSel | 4 × A | Varies | List of selected extended asymmetric key signature algorithms |
| 32 + 4 × A | ExtHashSel | 4 × E | Varies | List of selected extended hashing algorithms |
| 32 + 4 × A + 4 × E | AlgStructSel | AlgStructSize | Varies | Selected algorithm structure tables |

### Algorithm Types

SPDM supports several types of cryptographic algorithms that can be negotiated:

#### Measurement Specification

| Value | Name | Description |
|-------|------|-------------|
| 0x01 | DMTF | DMTF measurement specification |

#### Base Hash Algorithms

| Value | Name | Description |
|-------|------|-------------|
| 0x00000001 | TPM_ALG_SHA_256 | SHA-256 (required) |
| 0x00000002 | TPM_ALG_SHA_384 | SHA-384 |
| 0x00000004 | TPM_ALG_SHA_512 | SHA-512 |
| 0x00000008 | TPM_ALG_SHA3_256 | SHA3-256 |
| 0x00000010 | TPM_ALG_SHA3_384 | SHA3-384 |
| 0x00000020 | TPM_ALG_SHA3_512 | SHA3-512 |
| 0x00000040 | TPM_ALG_SM3_256 | SM3-256 |

#### Base Asymmetric Algorithms

| Value | Name | Description |
|-------|------|-------------|
| 0x00000001 | TPM_ALG_RSA_SSA | RSA SSA (2048-bit or larger) |
| 0x00000002 | TPM_ALG_RSAPSS | RSA PSS (2048-bit or larger) |
| 0x00000004 | TPM_ALG_ECDSA_ECC_NIST_P256 | ECDSA with NIST P-256 |
| 0x00000008 | TPM_ALG_RSASSA_2048 | RSA SSA (2048-bit) |
| 0x00000010 | TPM_ALG_RSASSA_3072 | RSA SSA (3072-bit) |
| 0x00000020 | TPM_ALG_RSASSA_4096 | RSA SSA (4096-bit) |
| 0x00000040 | TPM_ALG_RSAPSS_2048 | RSA PSS (2048-bit) |
| 0x00000080 | TPM_ALG_RSAPSS_3072 | RSA PSS (3072-bit) |
| 0x00000100 | TPM_ALG_RSAPSS_4096 | RSA PSS (4096-bit) |
| 0x00000200 | TPM_ALG_SM2_ECC_SM2_P256 | SM2 with SM2 P-256 (SPDM 1.2+) |
| 0x00000400 | TPM_ALG_EDDSA_ED25519 | EdDSA with Ed25519 (SPDM 1.2+) |
| 0x00000800 | TPM_ALG_EDDSA_ED448 | EdDSA with Ed448 (SPDM 1.2+) |

#### DHE Named Groups (SPDM 1.1+)

| Value | Name | Description |
|-------|------|-------------|
| 0x0001 | FFDHE_2048 | Finite Field DHE 2048-bit |
| 0x0002 | FFDHE_3072 | Finite Field DHE 3072-bit |
| 0x0004 | FFDHE_4096 | Finite Field DHE 4096-bit |
| 0x0008 | SECP_256_R1 | ECDHE with NIST P-256 |
| 0x0010 | SECP_384_R1 | ECDHE with NIST P-384 |
| 0x0020 | SECP_521_R1 | ECDHE with NIST P-521 |
| 0x0040 | SM2_P256 | ECDHE with SM2 P-256 (SPDM 1.2+) |

#### AEAD Cipher Suites (SPDM 1.1+)

| Value | Name | Description |
|-------|------|-------------|
| 0x0001 | AES_128_GCM | AES-128 in GCM mode |
| 0x0002 | AES_256_GCM | AES-256 in GCM mode |
| 0x0004 | CHACHA20_POLY1305 | ChaCha20-Poly1305 |
| 0x0008 | SM4_128_GCM | SM4-128 in GCM mode (SPDM 1.2+) |

#### Key Schedule Methods (SPDM 1.1+)

| Value | Name | Description |
|-------|------|-------------|
| 0x0001 | SPDM_KEY_SCHEDULE | SPDM key schedule |

### Protocol Flow

1. **Requester Action**:
   - The Requester constructs a NEGOTIATE_ALGORITHMS request message
   - The Requester includes all its supported algorithms in the request
   - The Requester sends the NEGOTIATE_ALGORITHMS request to the Responder
   - The Requester waits for an ALGORITHMS response

2. **Responder Action**:
   - The Responder receives the NEGOTIATE_ALGORITHMS request
   - The Responder validates the request format
   - The Responder compares the Requester's algorithms with its own supported algorithms
   - The Responder selects the algorithms to use based on preference and mutual support
   - The Responder constructs an ALGORITHMS response with the selected algorithms
   - The Responder sends the ALGORITHMS response to the Requester

3. **Algorithm Selection**:
   - The Requester receives the ALGORITHMS response
   - The Requester validates the response format
   - The Requester verifies that the selected algorithms are supported
   - The Requester records the selected algorithms for future use

### State Management

The NEGOTIATE_ALGORITHMS command has significant effects on the SPDM state machine:

1. **State Verification**:
   - The Responder verifies that GET_CAPABILITIES has been completed successfully
   - If not, the Responder returns an UNEXPECTED_REQUEST error

2. **Algorithm Recording**:
   - Both parties record the negotiated algorithms for future use
   - The selected algorithms are used for all subsequent cryptographic operations

3. **Connection State**:
   - After successful algorithm negotiation, the connection state is set to NEGOTIATED_ALGORITHMS
   - This allows the protocol to proceed to the authentication phase

4. **Transcript Management**:
   - The NEGOTIATE_ALGORITHMS request and ALGORITHMS response are added to the transcript buffer A
   - This transcript is used for subsequent message authentication

### Error Handling

The NEGOTIATE_ALGORITHMS command can encounter several error conditions:

1. **Invalid State**:
   - If GET_CAPABILITIES has not been completed successfully
   - Response: ERROR with code UNEXPECTED_REQUEST (0x03)

2. **Invalid Request Format**:
   - If the request size is incorrect for the SPDM version
   - If the request contains invalid parameters
   - Response: ERROR with code INVALID_REQUEST (0x01)

3. **Unsupported Algorithms**:
   - If the Requester and Responder have no common algorithms
   - Response: ERROR with code INVALID_REQUEST (0x01)

4. **Invalid Algorithm Combinations**:
   - If the requested algorithms are incompatible with each other
   - Response: ERROR with code INVALID_REQUEST (0x01)

5. **Busy State**:
   - If the Responder is temporarily unable to process the request
   - Response: ERROR with code BUSY (0x02)
   - The Requester should retry after a delay

### Retry Behavior

When the Requester receives an error response to a NEGOTIATE_ALGORITHMS request, it should follow these retry procedures:

1. **BUSY Error**:
   - Wait for the specified time (2^CT_Exponent μs) if provided
   - Retry the NEGOTIATE_ALGORITHMS request
   - Continue retrying until successful or retry limit is reached

2. **REQUEST_RESYNCH Error**:
   - Reset the local context
   - Restart the SPDM communication with GET_VERSION

3. **Other Errors**:
   - Terminate the SPDM communication
   - Report the error to higher layers

### Implementation Considerations

1. **Algorithm Preference**:
   - Implementations should prioritize stronger algorithms
   - The Responder selects from the algorithms offered by the Requester
   - If multiple algorithms are supported, the Responder should select the strongest one

2. **Algorithm Compatibility**:
   - Implementations must ensure that selected algorithms are compatible
   - For example, the hash algorithm used for measurements should be compatible with the base hash algorithm

3. **Version Compatibility**:
   - Implementations must adjust the request and response formats based on the negotiated SPDM version
   - Fields not defined in earlier versions must be omitted

4. **Security Implications**:
   - The NEGOTIATE_ALGORITHMS exchange is not authenticated
   - Attackers could potentially downgrade the cryptographic strength
   - Later authentication steps help mitigate this risk

5. **Algorithm Structure Tables**:
   - In SPDM 1.1+, algorithm structure tables must be included in order of AlgType
   - The number of tables must match the value in the header's param1 field

### NEGOTIATE_ALGORITHMS Examples

#### SPDM 1.0 Example

**Request (MCTP + SPDM)**:
```
05 10 E3 00 00 40 00 01 00 00 00 00 04 00 00 00 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `E3`: RequestResponseCode (NEGOTIATE_ALGORITHMS)
- `00`: Param1 (0 algorithm structure tables)
- `00`: Param2 (Reserved)
- `40 00`: Length (64 bytes)
- `01`: MeasurementSpecification (DMTF)
- `00`: OtherParamsSupport (None)
- `00 00 00 04`: BaseAsymAlgo (TPM_ALG_ECDSA_ECC_NIST_P256)
- `00 00 00 07`: BaseHashAlgo (SHA-256, SHA-384, SHA-512)
- `00 00 00 00 00 00 00 00 00 00 00 00`: Reserved bytes
- `00`: ExtAsymCount (0)
- `00`: ExtHashCount (0)
- `00 00`: Reserved bytes

**Response (MCTP + SPDM)**:
```
05 10 63 00 00 24 00 01 00 00 00 00 01 00 00 00 04 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `63`: RequestResponseCode (ALGORITHMS)
- `00`: Param1 (0 algorithm structure tables)
- `00`: Param2 (Reserved)
- `24 00`: Length (36 bytes)
- `01`: MeasurementSpecificationSel (DMTF)
- `00`: OtherParamsSelSupport (None)
- `00 00 00 01`: MeasurementHashAlgo (SHA-256)
- `00 00 00 04`: BaseAsymAlgoSel (TPM_ALG_ECDSA_ECC_NIST_P256)
- `00 00 00 01`: BaseHashAlgoSel (SHA-256)
- `00 00 00 00 00 00 00 00 00 00 00 00`: Reserved bytes
- `00`: ExtAsymSelCount (0)
- `00`: ExtHashSelCount (0)
- `00 00`: Reserved bytes

#### SPDM 1.1 Example

**Request (MCTP + SPDM)**:
```
05 11 E3 04 00 60 00 01 00 00 00 00 04 00 00 00 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 20 00 08 03 20 00 01 04 20 00 04 05 20 00 01
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `11`: SPDMVersion (SPDM 1.1)
- `E3`: RequestResponseCode (NEGOTIATE_ALGORITHMS)
- `04`: Param1 (4 algorithm structure tables)
- `00`: Param2 (Reserved)
- `60 00`: Length (96 bytes)
- `01`: MeasurementSpecification (DMTF)
- `00`: OtherParamsSupport (None)
- `00 00 00 04`: BaseAsymAlgo (TPM_ALG_ECDSA_ECC_NIST_P256)
- `00 00 00 07`: BaseHashAlgo (SHA-256, SHA-384, SHA-512)
- `00 00 00 00 00 00 00 00 00 00 00 00`: Reserved bytes
- `00`: ExtAsymCount (0)
- `00`: ExtHashCount (0)
- `00 00`: Reserved bytes
- Algorithm structure tables:
  - `02 20 00 08`: DHE named groups (SECP_256_R1)
  - `03 20 00 01`: AEAD cipher suites (AES_128_GCM)
  - `04 20 00 04`: Requester base asymmetric algorithms (TPM_ALG_ECDSA_ECC_NIST_P256)
  - `05 20 00 01`: Key schedule methods (SPDM_KEY_SCHEDULE)

**Response (MCTP + SPDM)**:
```
05 11 63 04 00 44 00 01 00 00 00 00 01 00 00 00 04 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 02 20 00 08 03 20 00 01 04 20 00 04 05 20 00 01
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `11`: SPDMVersion (SPDM 1.1)
- `63`: RequestResponseCode (ALGORITHMS)
- `04`: Param1 (4 algorithm structure tables)
- `00`: Param2 (Reserved)
- `44 00`: Length (68 bytes)
- `01`: MeasurementSpecificationSel (DMTF)
- `00`: OtherParamsSelSupport (None)
- `00 00 00 01`: MeasurementHashAlgo (SHA-256)
- `00 00 00 04`: BaseAsymAlgoSel (TPM_ALG_ECDSA_ECC_NIST_P256)
- `00 00 00 01`: BaseHashAlgoSel (SHA-256)
- `00 00 00 00 00 00 00 00 00 00 00 00`: Reserved bytes
- `00`: ExtAsymSelCount (0)
- `00`: ExtHashSelCount (0)
- `00 00`: Reserved bytes
- Algorithm structure tables:
  - `02 20 00 08`: DHE named groups selection (SECP_256_R1)
  - `03 20 00 01`: AEAD cipher suites selection (AES_128_GCM)
  - `04 20 00 04`: Requester base asymmetric algorithms selection (TPM_ALG_ECDSA_ECC_NIST_P256)
  - `05 20 00 01`: Key schedule methods selection (SPDM_KEY_SCHEDULE)

#### Error Response Example

**UNEXPECTED_REQUEST Error Response (MCTP + SPDM)**:
```
05 10 7F 03 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `7F`: RequestResponseCode (ERROR)
- `03`: Error code (UNEXPECTED_REQUEST)
- `00`: Error data

**INVALID_REQUEST Error Response (MCTP + SPDM)**:
```
05 10 7F 01 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `10`: SPDMVersion (SPDM 1.0)
- `7F`: RequestResponseCode (ERROR)
- `01`: Error code (INVALID_REQUEST)
- `00`: Error data

## GET_DIGESTS Command

The GET_DIGESTS command is the first message in the SPDM Authentication Phase and is used to retrieve the digests (hashes) of certificate chains stored in the Responder's certificate slots. This command must be sent after the Connection Phase is completed and before requesting specific certificates with GET_CERTIFICATE.

### Purpose and Functionality

The GET_DIGESTS command serves several critical purposes in the SPDM protocol:

1. **Certificate Discovery**: Determines which certificate slots are populated in the Responder
2. **Certificate Verification**: Provides digests that can be used to verify certificate integrity
3. **Certificate Selection**: Enables the Requester to choose which certificates to request
4. **Optimization**: Allows the Requester to skip requesting certificates it already has cached
5. **Multi-Key Support**: Provides information about multiple key pairs (SPDM 1.3+)

### Message Format

#### GET_DIGESTS Request

The GET_DIGESTS request has a simple format that is consistent across all SPDM versions:

```
+----------------+----------------+----------------+
| SPDM Header    | Param1 (0x00)  | Param2 (0x00)  |
+----------------+----------------+----------------+
```

Detailed field breakdown:

| Field | Size (bytes) | Value | Description |
|-------|--------------|-------|-------------|
| SPDM Header | 1 | 0x81 | Bits 7-4: SPDM version<br>Bits 3-0: 0x1 (GET_DIGESTS) |
| Param1 | 1 | 0x00 | Reserved, must be 0 |
| Param2 | 1 | 0x00 | Reserved, must be 0 |

**Important Notes**:
- The GET_DIGESTS request is a simple query with no additional parameters
- The request format is the same for all SPDM versions

#### DIGESTS Response

The DIGESTS response format varies slightly based on the SPDM version:

**SPDM 1.0-1.2 Format**:
```
+----------------+----------------+----------------+----------------+
| SPDM Header    | Param1 (0x00)  | Param2         | Digest[0]      |
+----------------+----------------+----------------+----------------+
| Digest[1]      | ...            | Digest[7]      |
+----------------+----------------+----------------+
```

**SPDM 1.3+ Format**:
```
+----------------+----------------+----------------+----------------+
| SPDM Header    | Param1         | Param2         | Digest[0]      |
+----------------+----------------+----------------+----------------+
| Digest[1]      | ...            | Digest[7]      | KeyPairID[0]   |
+----------------+----------------+----------------+----------------+
| KeyPairID[1]   | ...            | KeyPairID[7]   | CertInfo[0]    |
+----------------+----------------+----------------+----------------+
| CertInfo[1]    | ...            | CertInfo[7]    | KeyUsage[0]    |
+----------------+----------------+----------------+----------------+
| KeyUsage[1]    | ...            | KeyUsage[7]    |
+----------------+----------------+----------------+
```

Detailed field breakdown:

| Field | Size (bytes) | Description |
|-------|--------------|-------------|
| SPDM Header | 1 | Bits 7-4: SPDM version<br>Bits 3-0: 0x01 (DIGESTS) |
| Param1 | 1 | SPDM 1.0-1.2: Reserved, must be 0<br>SPDM 1.3+: Supported slot mask |
| Param2 | 1 | Slot mask indicating which slots contain certificate chains |
| Digest[i] | H × SlotCount | Array of digests, where H is the hash size in bytes |
| KeyPairID[i] | 1 × SlotCount | Array of key pair IDs (SPDM 1.3+ with multi-key support) |
| CertInfo[i] | 1 × SlotCount | Array of certificate information (SPDM 1.3+ with multi-key support) |
| KeyUsage[i] | 2 × SlotCount | Array of key usage bit masks (SPDM 1.3+ with multi-key support) |

**Important Notes**:
- The digest size (H) depends on the negotiated hash algorithm
- The number of digests (SlotCount) is determined by the number of bits set in the slot mask (Param2)
- In SPDM 1.3+, Param1 indicates which slots are supported by the Responder
- The additional fields (KeyPairID, CertInfo, KeyUsage) are only present in SPDM 1.3+ when multi-key connection is enabled

### Certificate Chain Slots

SPDM supports up to 8 certificate chain slots, numbered from 0 to 7. Each slot can contain a complete certificate chain or be empty. The slot mask in the DIGESTS response indicates which slots are populated:

| Bit Position | Meaning |
|--------------|----------|
| Bit 0 | Slot 0 contains a certificate chain if set to 1 |
| Bit 1 | Slot 1 contains a certificate chain if set to 1 |
| ... | ... |
| Bit 7 | Slot 7 contains a certificate chain if set to 1 |

In SPDM 1.3+, the supported slot mask (Param1) and provisioned slot mask (Param2) together provide more detailed information about the state of each slot:

| Supported Slot Mask | Provisioned Slot Mask | Certificate Model | Slot State |
|---------------------|------------------------|-------------------|------------|
| 0 | N/A | N/A | Slot does not exist |
| 1 | 0 | N/A | Slot exists but is empty |
| 1 | 1 | 0 | Slot exists with key only |
| 1 | 1 | Non-zero | Slot exists with key and certificate |

#### Multi-Key Support (SPDM 1.3+)

When multi-key connection is enabled in SPDM 1.3+, the DIGESTS response includes additional information about each certificate:

1. **Key Pair ID**: Identifies the key pair associated with the certificate
2. **Certificate Information**: Provides details about the certificate model
   - Bits 0-3: Certificate model (0 = No certificate, 1 = X.509, 2-15 = Reserved)
   - Bits 4-7: Reserved
3. **Key Usage Bit Mask**: Indicates the allowed usage of the key
   - Bit 0: Digital signature
   - Bit 1: Key exchange
   - Bit 2: Challenge-response
   - Bits 3-15: Reserved

### Protocol Flow

1. **Requester Action**:
   - The Requester constructs a GET_DIGESTS request message
   - The Requester sends the GET_DIGESTS request to the Responder
   - The Requester waits for a DIGESTS response

2. **Responder Action**:
   - The Responder receives the GET_DIGESTS request
   - The Responder validates the request format
   - The Responder checks if it has the CERT_CAP capability
   - The Responder calculates the digest of each certificate chain it has
   - The Responder constructs a DIGESTS response with the slot mask and digests
   - The Responder sends the DIGESTS response to the Requester

3. **Digest Processing**:
   - The Requester receives the DIGESTS response
   - The Requester validates the response format
   - The Requester examines the slot mask to determine which slots have certificates
   - The Requester may compare the digests with previously cached values
   - The Requester decides which certificates to request with GET_CERTIFICATE

### State Management

The GET_DIGESTS command has significant effects on the SPDM state machine:

1. **State Verification**:
   - The Responder verifies that the Connection Phase has been completed successfully
   - If not, the Responder returns an UNEXPECTED_REQUEST error
   - The Responder verifies that it has the CERT_CAP capability
   - If not, the Responder returns an UNSUPPORTED_REQUEST error

2. **Transcript Management**:
   - The GET_DIGESTS request and DIGESTS response are added to the transcript buffer B
   - This transcript is used for subsequent message authentication
   - In a session context, the transcript is added to the session transcript

3. **Connection State**:
   - After successful digest exchange, the connection state remains in NEGOTIATED_ALGORITHMS
   - This allows the protocol to proceed to certificate retrieval

### Error Handling

The GET_DIGESTS command can encounter several error conditions:

1. **Invalid State**:
   - If the Connection Phase has not been completed successfully
   - Response: ERROR with code UNEXPECTED_REQUEST (0x03)

2. **Unsupported Capability**:
   - If the Responder does not have the CERT_CAP capability
   - Response: ERROR with code UNSUPPORTED_REQUEST (0x05)

3. **Invalid Request Format**:
   - If the request size is incorrect
   - If the request contains invalid parameters
   - Response: ERROR with code INVALID_REQUEST (0x01)

4. **Version Mismatch**:
   - If the SPDM version in the request does not match the negotiated version
   - Response: ERROR with code VERSION_MISMATCH (0x06)

5. **Busy State**:
   - If the Responder is temporarily unable to process the request
   - Response: ERROR with code BUSY (0x02)
   - The Requester should retry after a delay

6. **Internal Error**:
   - If the Responder encounters an internal error while generating digests
   - Response: ERROR with code UNSPECIFIED (0x04)

### Retry Behavior

When the Requester receives an error response to a GET_DIGESTS request, it should follow these retry procedures:

1. **BUSY Error**:
   - Wait for the specified time (2^CT_Exponent μs) if provided
   - Retry the GET_DIGESTS request
   - Continue retrying until successful or retry limit is reached

2. **RESPONSE_NOT_READY Error**:
   - Send RESPOND_IF_READY with the same request code
   - Wait for the response or another error

3. **REQUEST_RESYNCH Error**:
   - Reset the local context
   - Restart the SPDM communication with GET_VERSION

4. **Other Errors**:
   - Terminate the SPDM communication
   - Report the error to higher layers

### Implementation Considerations

1. **Certificate Chain Handling**:
   - Implementations should support at least one certificate slot
   - Multiple slots can be used for different purposes or security levels
   - Each slot should contain a complete certificate chain from end-entity to root

2. **Digest Calculation**:
   - The digest is calculated over the entire certificate chain, not just the end-entity certificate
   - The hash algorithm used is the one negotiated during NEGOTIATE_ALGORITHMS

3. **Caching Strategy**:
   - Requesters can cache certificate chains and their digests
   - If a digest matches a cached value, the Requester can skip requesting that certificate

4. **Multi-Key Support**:
   - In SPDM 1.3+, implementations should handle the additional fields for multi-key support
   - The key usage bit mask should be checked to ensure the key is used for its intended purpose

5. **Security Implications**:
   - The GET_DIGESTS exchange is not authenticated in the base protocol
   - Attackers could potentially provide false digests
   - Later authentication steps help mitigate this risk

### GET_DIGESTS Examples

#### SPDM 1.1 Example with One Certificate

**Request (MCTP + SPDM)**:
```
05 81 00 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `81`: SPDM header (version 1.1, request code 0x1 for GET_DIGESTS)
- `00 00`: Param1 (0) and Param2 (0)

**Response (MCTP + SPDM)**:
```
05 01 00 01 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `01`: SPDM header (version 1.1, response code 0x1 for DIGESTS)
- `00`: Param1 (0, reserved)
- `01`: Param2 (slot mask 0x01, indicating slot 0 has a certificate)
- `00 01 02...1F`: SHA-256 digest of the certificate chain in slot 0 (32 bytes)

#### SPDM 1.1 Example with Multiple Certificates

**Request (MCTP + SPDM)**:
```
05 81 00 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `81`: SPDM header (version 1.1, request code 0x1 for GET_DIGESTS)
- `00 00`: Param1 (0) and Param2 (0)

**Response (MCTP + SPDM)**:
```
05 01 00 05 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `01`: SPDM header (version 1.1, response code 0x1 for DIGESTS)
- `00`: Param1 (0, reserved)
- `05`: Param2 (slot mask 0x05, indicating slots 0 and 2 have certificates)
- `00 01 02...1F`: SHA-256 digest of the certificate chain in slot 0 (32 bytes)
- `20 21 22...3F`: SHA-256 digest of the certificate chain in slot 2 (32 bytes)

#### SPDM 1.3 Example with Multi-Key Support

**Request (MCTP + SPDM)**:
```
05 81 00 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `81`: SPDM header (version 1.3, request code 0x1 for GET_DIGESTS)
- `00 00`: Param1 (0) and Param2 (0)

**Response (MCTP + SPDM)**:
```
05 01 03 03 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 01 02 01 01 00 03 00 07
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `01`: SPDM header (version 1.3, response code 0x1 for DIGESTS)
- `03`: Param1 (supported slot mask 0x03, indicating slots 0 and 1 are supported)
- `03`: Param2 (provisioned slot mask 0x03, indicating slots 0 and 1 have certificates)
- `00 01 02...1F`: SHA-256 digest of the certificate chain in slot 0 (32 bytes)
- `20 21 22...3F`: SHA-256 digest of the certificate chain in slot 1 (32 bytes)
- `01`: Key pair ID for slot 0
- `02`: Key pair ID for slot 1
- `01`: Certificate info for slot 0 (X.509 certificate model)
- `01`: Certificate info for slot 1 (X.509 certificate model)
- `00 03`: Key usage bit mask for slot 0 (digital signature and challenge-response)
- `00 07`: Key usage bit mask for slot 1 (digital signature, key exchange, and challenge-response)

#### Error Response Example

**UNSUPPORTED_REQUEST Error Response (MCTP + SPDM)**:
```
05 7F 05 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `7F`: SPDM header (version 1.0, response code 0x7F for ERROR)
- `05`: Error code (UNSUPPORTED_REQUEST)
- `00`: Error data

## GET_CERTIFICATE Command

The GET_CERTIFICATE command is the second message in the SPDM Authentication Phase and is used to retrieve the certificate chains stored in the Responder's certificate slots. This command must be sent after GET_DIGESTS and before CHALLENGE to obtain the certificates needed for authentication.

### Purpose and Functionality

The GET_CERTIFICATE command serves several critical purposes in the SPDM protocol:

1. **Certificate Retrieval**: Obtains the complete certificate chain from a specific slot
2. **Identity Verification**: Provides the certificates needed to verify the Responder's identity
3. **Trust Establishment**: Enables the Requester to establish a chain of trust to the Responder
4. **Incremental Retrieval**: Allows large certificate chains to be retrieved in smaller portions
5. **Certificate Validation**: Provides the certificates needed for cryptographic validation

### Message Format

#### GET_CERTIFICATE Request

The GET_CERTIFICATE request format is consistent across all SPDM versions with minor additions in SPDM 1.3:

```
+----------------+----------------+----------------+----------------+----------------+
| SPDM Header    | Param1         | Param2         | Offset         | Length         |
+----------------+----------------+----------------+----------------+----------------+
```

Detailed field breakdown:

| Field | Size (bytes) | Description |
|-------|--------------|-------------|
| SPDM Header | 1 | Bits 7-4: SPDM version<br>Bits 3-0: 0x2 (GET_CERTIFICATE) |
| Param1 | 1 | Bits 0-3: Slot ID (0-7)<br>Bits 4-7: Reserved, must be 0 |
| Param2 | 1 | SPDM 1.0-1.2: Reserved, must be 0<br>SPDM 1.3+: Request attributes |
| Offset | 2 | Offset within the certificate chain to start retrieval |
| Length | 2 | Length of the certificate chain portion to retrieve |

**Request Attributes (SPDM 1.3+)**:
| Bit | Name | Description |
|-----|------|-------------|
| 0 | SLOT_SIZE_REQUESTED | If set, requests the total size of the certificate chain in the slot |

**Important Notes**:
- The Slot ID must match one of the slots indicated in the DIGESTS response
- If SLOT_SIZE_REQUESTED is set in SPDM 1.3+, the Offset and Length fields are ignored
- The maximum length that can be requested in a single message depends on the transport layer and negotiated capabilities

#### CERTIFICATE Response

The CERTIFICATE response format is consistent across all SPDM versions with minor additions in SPDM 1.3:

```
+----------------+----------------+----------------+----------------+----------------+----------------+
| SPDM Header    | Param1         | Param2         | PortionLength  | RemainderLength| CertChain      |
+----------------+----------------+----------------+----------------+----------------+----------------+
```

Detailed field breakdown:

| Field | Size (bytes) | Description |
|-------|--------------|-------------|
| SPDM Header | 1 | Bits 7-4: SPDM version<br>Bits 3-0: 0x2 (CERTIFICATE) |
| Param1 | 1 | Bits 0-3: Slot ID (0-7)<br>Bits 4-7: Reserved, must be 0 |
| Param2 | 1 | SPDM 1.0-1.2: Reserved, must be 0<br>SPDM 1.3+: Certificate information |
| PortionLength | 2 | Length of the certificate chain portion in this response |
| RemainderLength | 2 | Length of the remaining certificate chain not included in this response |
| CertChain | PortionLength | The certificate chain portion data |

**Certificate Information (SPDM 1.3+)**:
| Bits | Name | Description |
|------|------|-------------|
| 0-3 | Certificate Model | 0: No certificate<br>1: X.509<br>2-15: Reserved |
| 4-7 | Reserved | Must be 0 |

**Important Notes**:
- The Slot ID in the response must match the Slot ID in the request
- The PortionLength indicates how many bytes of the certificate chain are included in this response
- The RemainderLength indicates how many bytes remain to be retrieved in subsequent requests
- If RemainderLength is 0, the entire certificate chain has been retrieved

### Certificate Chain Format

The certificate chain in SPDM follows a specific format defined in the specification:

```
+----------------+----------------+----------------+----------------+
| Length         | RootHash       | Certificate[0] | Certificate[1] | ... | Certificate[n] |
+----------------+----------------+----------------+----------------+----------------+----------------+
```

Detailed field breakdown:

| Field | Size (bytes) | Description |
|-------|--------------|-------------|
| Length | 4 | Total length of the certificate chain including this field |
| RootHash | H | Hash of the Root Certificate (Certificate[0])<br>Size H depends on the negotiated hash algorithm |
| Certificate[i] | Varies | ASN.1 DER-encoded X.509 v3 certificates |

**Certificate Chain Requirements**:

1. **Certificate Format**: Each certificate must be in ASN.1 DER-encoded X.509 v3 format as defined in RFC 5280
2. **Certificate Order**: The certificates must be ordered from root (Certificate[0]) to leaf (Certificate[n])
3. **Certificate Chain**: Each certificate (except the root) must be signed by the previous certificate in the chain
4. **Root Hash**: The root hash must be calculated using the negotiated hash algorithm over the root certificate
5. **Leaf Certificate**: The leaf certificate (Certificate[n]) represents the Responder's identity

**Certificate Validation Requirements**:

1. **Chain Validation**: The Requester must validate the certificate chain from root to leaf
2. **Root Trust**: The Requester must have a way to verify the root certificate (e.g., pre-provisioned root hash)
3. **Revocation**: The Requester should check for certificate revocation if possible
4. **Key Usage**: The leaf certificate must have appropriate key usage extensions for its intended purpose

### Protocol Flow

1. **Requester Action**:
   - The Requester determines which certificate slot to request based on the DIGESTS response
   - The Requester constructs a GET_CERTIFICATE request with the desired slot ID, offset, and length
   - The Requester sends the GET_CERTIFICATE request to the Responder
   - The Requester waits for a CERTIFICATE response

2. **Responder Action**:
   - The Responder receives the GET_CERTIFICATE request
   - The Responder validates the request format and parameters
   - The Responder checks if it has a certificate chain in the requested slot
   - The Responder extracts the portion of the certificate chain specified by the offset and length
   - The Responder constructs a CERTIFICATE response with the certificate chain portion
   - The Responder sends the CERTIFICATE response to the Requester

3. **Certificate Retrieval Process**:
   - The Requester receives the CERTIFICATE response
   - The Requester validates the response format
   - The Requester appends the certificate chain portion to any previously retrieved portions
   - If RemainderLength is not 0, the Requester sends another GET_CERTIFICATE request with an updated offset
   - This process continues until the entire certificate chain is retrieved (RemainderLength = 0)

4. **Certificate Validation**:
   - Once the complete certificate chain is retrieved, the Requester validates it
   - The Requester verifies the root hash matches a trusted value
   - The Requester validates the certificate chain from root to leaf
   - The Requester extracts the public key from the leaf certificate for later use in CHALLENGE

### State Management

The GET_CERTIFICATE command has significant effects on the SPDM state machine:

1. **State Verification**:
   - The Responder verifies that GET_DIGESTS has been completed successfully
   - If not, the Responder returns an UNEXPECTED_REQUEST error
   - The Responder verifies that it has the CERT_CAP capability
   - If not, the Responder returns an UNSUPPORTED_REQUEST error

2. **Transcript Management**:
   - The GET_CERTIFICATE request and CERTIFICATE response are added to the transcript buffer B
   - This transcript is used for subsequent message authentication
   - In a session context, the transcript is added to the session transcript

3. **Connection State**:
   - After successful certificate retrieval, the connection state remains in NEGOTIATED_ALGORITHMS
   - This allows the protocol to proceed to the CHALLENGE phase

### Error Handling

The GET_CERTIFICATE command can encounter several error conditions:

1. **Invalid State**:
   - If GET_DIGESTS has not been completed successfully
   - Response: ERROR with code UNEXPECTED_REQUEST (0x03)

2. **Unsupported Capability**:
   - If the Responder does not have the CERT_CAP capability
   - Response: ERROR with code UNSUPPORTED_REQUEST (0x05)

3. **Invalid Slot ID**:
   - If the requested slot ID is not valid or does not contain a certificate
   - Response: ERROR with code INVALID_REQUEST (0x01)

4. **Invalid Offset or Length**:
   - If the offset is beyond the end of the certificate chain
   - If the length is too large for the transport layer
   - Response: ERROR with code INVALID_REQUEST (0x01)

5. **Reset Required**:
   - If the certificate slot has been reset and requires re-provisioning (SPDM 1.2+)
   - Response: ERROR with code RESET_REQUIRED (0x0B)

6. **Busy State**:
   - If the Responder is temporarily unable to process the request
   - Response: ERROR with code BUSY (0x02)
   - The Requester should retry after a delay

### Retry Behavior

When the Requester receives an error response to a GET_CERTIFICATE request, it should follow these retry procedures:

1. **BUSY Error**:
   - Wait for the specified time (2^CT_Exponent μs) if provided
   - Retry the GET_CERTIFICATE request
   - Continue retrying until successful or retry limit is reached

2. **RESPONSE_NOT_READY Error**:
   - Send RESPOND_IF_READY with the same request code
   - Wait for the response or another error

3. **REQUEST_RESYNCH Error**:
   - Reset the local context
   - Restart the SPDM communication with GET_VERSION

4. **RESET_REQUIRED Error**:
   - The certificate slot needs to be re-provisioned
   - This is typically handled at a higher layer

5. **Other Errors**:
   - Terminate the SPDM communication
   - Report the error to higher layers

### Implementation Considerations

1. **Certificate Chain Size**:
   - Certificate chains can be large (several KB)
   - Implementations should support retrieving certificates in multiple portions
   - The maximum portion size should be chosen based on transport layer limitations

2. **Certificate Validation**:
   - Implementations must properly validate the certificate chain
   - The root certificate should be verified against a trusted root hash
   - Certificate validation should include expiration, revocation, and key usage checks

3. **Memory Management**:
   - Implementations should efficiently manage memory when handling large certificate chains
   - Consider using streaming approaches for certificate validation

4. **Caching Strategy**:
   - Requesters can cache certificate chains to avoid repeated retrievals
   - Cache invalidation should occur if the digest changes

5. **Security Implications**:
   - The GET_CERTIFICATE exchange is not authenticated in the base protocol
   - Attackers could potentially provide false certificates
   - Later authentication steps help mitigate this risk

### GET_CERTIFICATE Examples

#### SPDM 1.1 Example with Single Request

**Request (MCTP + SPDM)**:
```
05 82 00 00 00 00 00 40
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `82`: SPDM header (version 1.1, request code 0x2 for GET_CERTIFICATE)
- `00`: Param1 (slot ID 0)
- `00`: Param2 (reserved)
- `00 00`: Offset (0)
- `00 40`: Length (64 bytes)

**Response (MCTP + SPDM)**:
```
05 02 00 00 00 40 01 C0 00 00 01 04 30 82 01 00 ... [certificate data] ...
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `02`: SPDM header (version 1.1, response code 0x2 for CERTIFICATE)
- `00`: Param1 (slot ID 0)
- `00`: Param2 (reserved)
- `00 40`: Portion length (64 bytes)
- `01 C0`: Remainder length (448 bytes)
- `00 00 01 04`: Certificate chain length (260 bytes)
- `30 82 01 00 ...`: Certificate chain data (ASN.1 DER-encoded X.509)

#### SPDM 1.1 Example with Multiple Requests

**First Request (MCTP + SPDM)**:
```
05 82 00 00 00 00 00 40
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `82`: SPDM header (version 1.1, request code 0x2 for GET_CERTIFICATE)
- `00`: Param1 (slot ID 0)
- `00`: Param2 (reserved)
- `00 00`: Offset (0)
- `00 40`: Length (64 bytes)

**First Response (MCTP + SPDM)**:
```
05 02 00 00 00 40 01 C0 00 00 01 04 30 82 01 00 ... [certificate data] ...
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `02`: SPDM header (version 1.1, response code 0x2 for CERTIFICATE)
- `00`: Param1 (slot ID 0)
- `00`: Param2 (reserved)
- `00 40`: Portion length (64 bytes)
- `01 C0`: Remainder length (448 bytes)
- `00 00 01 04`: Certificate chain length (260 bytes)
- `30 82 01 00 ...`: Certificate chain data (first 64 bytes)

**Second Request (MCTP + SPDM)**:
```
05 82 00 00 00 40 00 40
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `82`: SPDM header (version 1.1, request code 0x2 for GET_CERTIFICATE)
- `00`: Param1 (slot ID 0)
- `00`: Param2 (reserved)
- `00 40`: Offset (64 bytes)
- `00 40`: Length (64 bytes)

**Second Response (MCTP + SPDM)**:
```
05 02 00 00 00 40 01 80 ... [certificate data] ...
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `02`: SPDM header (version 1.1, response code 0x2 for CERTIFICATE)
- `00`: Param1 (slot ID 0)
- `00`: Param2 (reserved)
- `00 40`: Portion length (64 bytes)
- `01 80`: Remainder length (384 bytes)
- `...`: Certificate chain data (next 64 bytes)

#### SPDM 1.3 Example with Slot Size Request

**Request (MCTP + SPDM)**:
```
05 82 00 01 00 00 00 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `82`: SPDM header (version 1.3, request code 0x2 for GET_CERTIFICATE)
- `00`: Param1 (slot ID 0)
- `01`: Param2 (SLOT_SIZE_REQUESTED attribute)
- `00 00`: Offset (ignored)
- `00 00`: Length (ignored)

**Response (MCTP + SPDM)**:
```
05 02 00 01 00 00 02 00 00 00 02 04
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `02`: SPDM header (version 1.3, response code 0x2 for CERTIFICATE)
- `00`: Param1 (slot ID 0)
- `01`: Param2 (certificate model: X.509)
- `00 00`: Portion length (0 bytes)
- `02 00`: Remainder length (512 bytes)
- `00 00 02 04`: Certificate chain length (516 bytes)

#### Error Response Example

**INVALID_REQUEST Error Response (MCTP + SPDM)**:
```
05 7F 01 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `7F`: SPDM header (version 1.0, response code 0x7F for ERROR)
- `01`: Error code (INVALID_REQUEST)
- `00`: Error data

## CHALLENGE Command

The CHALLENGE command is the third and final message in the SPDM Authentication Phase and is used to authenticate the Responder by verifying its possession of the private key corresponding to the public key in its certificate. This command must be sent after retrieving the Responder's certificate with GET_CERTIFICATE and completes the authentication process.

### Purpose and Functionality

The CHALLENGE command serves several critical purposes in the SPDM protocol:

1. **Responder Authentication**: Verifies that the Responder possesses the private key corresponding to its certificate
2. **Freshness Verification**: Uses a random nonce to ensure the response is fresh and not replayed
3. **Transcript Validation**: Includes a signature over the transcript to prevent tampering with previous messages
4. **Measurement Verification**: Optionally includes a measurement summary hash for firmware integrity validation
5. **State Transition**: Transitions the connection to the authenticated state upon successful verification

### Message Format

#### CHALLENGE Request

The CHALLENGE request format is consistent across all SPDM versions with minor additions in SPDM 1.3:

```
+----------------+----------------+----------------+----------------+
| SPDM Header    | Param1         | Param2         | Nonce          |
+----------------+----------------+----------------+----------------+
| RequesterContext (SPDM 1.3+)    |
+----------------+----------------+
```

Detailed field breakdown:

| Field | Size (bytes) | Description |
|-------|--------------|-------------|
| SPDM Header | 1 | Bits 7-4: SPDM version<br>Bits 3-0: 0x3 (CHALLENGE) |
| Param1 | 1 | Slot ID (0-7) to use for authentication |
| Param2 | 1 | Measurement summary hash type |
| Nonce | 32 | Random nonce generated by the Requester |
| RequesterContext | 8 | Requester context data (SPDM 1.3+ only) |

**Measurement Summary Hash Type**:
| Value | Name | Description |
|-------|------|-------------|
| 0x00 | NO_MEASUREMENT_SUMMARY_HASH | No measurement summary hash requested |
| 0x01 | TCB_COMPONENT_MEASUREMENT_HASH | TCB component measurement hash requested |
| 0xFF | ALL_MEASUREMENTS_HASH | All measurements hash requested |

**Important Notes**:
- The Slot ID must match one of the slots indicated in the DIGESTS response
- The Nonce must be a cryptographically random value to prevent replay attacks
- The Measurement Summary Hash Type indicates what type of measurement hash is requested
- The RequesterContext is only present in SPDM 1.3+ and is used for mutual authentication

#### CHALLENGE_AUTH Response

The CHALLENGE_AUTH response format varies based on the SPDM version:

```
+----------------+----------------+----------------+----------------+
| SPDM Header    | Param1         | Param2         | CertChainHash  |
+----------------+----------------+----------------+----------------+
| Nonce          | MeasurementHash| OpaqueLength   | OpaqueData     |
+----------------+----------------+----------------+----------------+
| RequesterContext (SPDM 1.3+)    | Signature      |
+----------------+----------------+----------------+
```

Detailed field breakdown:

| Field | Size (bytes) | Description |
|-------|--------------|-------------|
| SPDM Header | 1 | Bits 7-4: SPDM version<br>Bits 3-0: 0x3 (CHALLENGE_AUTH) |
| Param1 | 1 | Bits 0-3: Slot ID (0-7) used for authentication<br>Bits 4-6: Reserved<br>Bit 7: Basic mutual authentication requested (deprecated in 1.2+) |
| Param2 | 1 | Slot mask indicating which slots contain certificate chains |
| CertChainHash | H | Hash of the certificate chain in the specified slot<br>Size H depends on the negotiated hash algorithm |
| Nonce | 32 | Copy of the random nonce from the CHALLENGE request |
| MeasurementHash | H | Measurement summary hash (if requested)<br>Size H depends on the negotiated hash algorithm |
| OpaqueLength | 2 | Length of the opaque data |
| OpaqueData | OpaqueLength | Opaque data (implementation-specific) |
| RequesterContext | 8 | Copy of the requester context from the request (SPDM 1.3+ only) |
| Signature | Varies | Signature over the transcript<br>Size depends on the negotiated asymmetric algorithm |

**Important Notes**:
- The Slot ID in the response must match the Slot ID in the request
- The Slot Mask is the same as returned in the DIGESTS response
- The Certificate Chain Hash is the hash of the certificate chain in the specified slot
- The Nonce must match exactly the nonce sent in the request
- The Measurement Summary Hash is only included if requested in the request
- The Signature is generated using the private key corresponding to the public key in the leaf certificate

### Signature Generation

The signature in the CHALLENGE_AUTH response is a critical security element that authenticates the Responder. The signature is generated over a specific set of data:

1. **Signature Context**: A fixed string "responder-challenge_auth signing"
2. **Transcript**: The concatenation of all previous messages in the authentication flow

The exact data signed depends on the SPDM version:

**SPDM 1.0**:
```
+----------------+----------------+----------------+----------------+
| Context        | GET_CERTIFICATE| CERTIFICATE    | CHALLENGE      |
+----------------+----------------+----------------+----------------+
| CHALLENGE_AUTH (without signature) |
+----------------+----------------+
```

**SPDM 1.1+**:
```
+----------------+----------------+----------------+----------------+
| Context        | GET_VERSION    | VERSION        | GET_CAPABILITIES|
+----------------+----------------+----------------+----------------+
| CAPABILITIES   | NEGOTIATE_ALGORITHMS | ALGORITHMS | GET_DIGESTS   |
+----------------+----------------+----------------+----------------+
| DIGESTS        | GET_CERTIFICATE| CERTIFICATE    | CHALLENGE      |
+----------------+----------------+----------------+----------------+
| CHALLENGE_AUTH (without signature) |
+----------------+----------------+
```

The signature algorithm used is the one negotiated during the NEGOTIATE_ALGORITHMS phase. The signature is verified by the Requester using the public key from the Responder's leaf certificate.

### Protocol Flow

1. **Requester Action**:
   - The Requester generates a random nonce
   - The Requester constructs a CHALLENGE request with the desired slot ID and measurement hash type
   - The Requester sends the CHALLENGE request to the Responder
   - The Requester waits for a CHALLENGE_AUTH response

2. **Responder Action**:
   - The Responder receives the CHALLENGE request
   - The Responder validates the request format and parameters
   - The Responder calculates the certificate chain hash
   - The Responder calculates the measurement summary hash (if requested)
   - The Responder constructs the CHALLENGE_AUTH response
   - The Responder generates a signature over the transcript
   - The Responder sends the CHALLENGE_AUTH response to the Requester

3. **Authentication Verification**:
   - The Requester receives the CHALLENGE_AUTH response
   - The Requester validates the response format
   - The Requester verifies that the nonce matches the one sent in the request
   - The Requester verifies that the certificate chain hash matches the expected value
   - The Requester verifies the signature using the public key from the Responder's certificate
   - If all verifications pass, the Requester considers the Responder authenticated

4. **Measurement Verification (Optional)**:
   - If a measurement summary hash was requested, the Requester validates it
   - The validation process depends on the specific measurement type and implementation

### State Management

The CHALLENGE command has significant effects on the SPDM state machine:

1. **State Verification**:
   - The Responder verifies that GET_CERTIFICATE has been completed successfully
   - If not, the Responder returns an UNEXPECTED_REQUEST error
   - The Responder verifies that it has the CHAL_CAP capability
   - If not, the Responder returns an UNSUPPORTED_REQUEST error

2. **Transcript Management**:
   - The CHALLENGE request is added to the transcript buffer C
   - The CHALLENGE_AUTH response (without signature) is added to the transcript buffer C
   - The signature is generated over the combined transcript (A + B + C)
   - After successful authentication, the transcript buffers are reset

3. **Connection State**:
   - After successful authentication, the connection state is set to AUTHENTICATED
   - This allows the protocol to proceed to the session establishment phase
   - If basic mutual authentication was requested (deprecated in 1.2+), the state remains in NEGOTIATED_ALGORITHMS

### Error Handling

The CHALLENGE command can encounter several error conditions:

1. **Invalid State**:
   - If GET_CERTIFICATE has not been completed successfully
   - Response: ERROR with code UNEXPECTED_REQUEST (0x03)

2. **Unsupported Capability**:
   - If the Responder does not have the CHAL_CAP capability
   - Response: ERROR with code UNSUPPORTED_REQUEST (0x05)

3. **Invalid Slot ID**:
   - If the requested slot ID is not valid or does not contain a certificate
   - Response: ERROR with code INVALID_REQUEST (0x01)

4. **Invalid Measurement Hash Type**:
   - If the requested measurement hash type is not supported
   - Response: ERROR with code INVALID_REQUEST (0x01)

5. **Signature Generation Failure**:
   - If the Responder fails to generate a valid signature
   - Response: ERROR with code UNSPECIFIED (0x04)

6. **Busy State**:
   - If the Responder is temporarily unable to process the request
   - Response: ERROR with code BUSY (0x02)
   - The Requester should retry after a delay

### Retry Behavior

When the Requester receives an error response to a CHALLENGE request, it should follow these retry procedures:

1. **BUSY Error**:
   - Wait for the specified time (2^CT_Exponent μs) if provided
   - Retry the CHALLENGE request
   - Continue retrying until successful or retry limit is reached

2. **RESPONSE_NOT_READY Error**:
   - Send RESPOND_IF_READY with the same request code
   - Wait for the response or another error

3. **REQUEST_RESYNCH Error**:
   - Reset the local context
   - Restart the SPDM communication with GET_VERSION

4. **Other Errors**:
   - Terminate the SPDM communication
   - Report the error to higher layers

### Implementation Considerations

1. **Nonce Generation**:
   - The nonce must be generated using a cryptographically secure random number generator
   - The nonce should never be reused for different CHALLENGE requests
   - The full 32 bytes of the nonce should be used to ensure sufficient entropy

2. **Signature Verification**:
   - The signature verification must use the exact same transcript as used for signature generation
   - The public key used for verification must be extracted from the leaf certificate
   - The signature algorithm must match the one negotiated during NEGOTIATE_ALGORITHMS

3. **Measurement Verification**:
   - If measurement verification is used, the implementation should have a secure way to validate the measurements
   - The measurement verification policy depends on the specific use case and security requirements

4. **Mutual Authentication**:
   - In SPDM 1.0-1.1, basic mutual authentication can be requested by setting bit 7 in Param1 of the response
   - In SPDM 1.2+, this is deprecated and mutual authentication is handled differently

5. **Security Implications**:
   - The CHALLENGE exchange is the critical security step that authenticates the Responder
   - A failure in nonce generation, signature verification, or transcript management can lead to security vulnerabilities
   - Implementations should be carefully tested and validated

### CHALLENGE Examples

#### SPDM 1.1 Example with No Measurement Hash

**Request (MCTP + SPDM)**:
```
05 83 00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `83`: SPDM header (version 1.1, request code 0x3 for CHALLENGE)
- `00`: Param1 (slot ID 0)
- `00`: Param2 (NO_MEASUREMENT_SUMMARY_HASH)
- `01 02 03...20`: 32-byte random nonce

**Response (MCTP + SPDM)**:
```
05 03 00 01 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 00 00 [signature bytes...]
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `03`: SPDM header (version 1.1, response code 0x3 for CHALLENGE_AUTH)
- `00`: Param1 (slot ID 0, no mutual authentication requested)
- `01`: Param2 (slot mask 0x01, indicating slot 0 has a certificate)
- `00 01 02...1F`: 32-byte certificate chain hash
- `01 02 03...20`: 32-byte nonce (matching the request)
- `00 00 00...00`: 32-byte measurement summary hash (all zeros since not requested)
- `00 00`: Opaque data length (0)
- `[signature bytes...]`: Signature over the transcript

#### SPDM 1.1 Example with Measurement Hash

**Request (MCTP + SPDM)**:
```
05 83 00 FF 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `83`: SPDM header (version 1.1, request code 0x3 for CHALLENGE)
- `00`: Param1 (slot ID 0)
- `FF`: Param2 (ALL_MEASUREMENTS_HASH)
- `21 22 23...40`: 32-byte random nonce

**Response (MCTP + SPDM)**:
```
05 03 00 01 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F 00 05 6C 69 62 73 70 64 6D [signature bytes...]
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `03`: SPDM header (version 1.1, response code 0x3 for CHALLENGE_AUTH)
- `00`: Param1 (slot ID 0, no mutual authentication requested)
- `01`: Param2 (slot mask 0x01, indicating slot 0 has a certificate)
- `00 01 02...1F`: 32-byte certificate chain hash
- `21 22 23...40`: 32-byte nonce (matching the request)
- `41 42 43...5F`: 32-byte measurement summary hash
- `00 05`: Opaque data length (5 bytes)
- `6C 69 62 73 70 64 6D`: Opaque data ("libspdm")
- `[signature bytes...]`: Signature over the transcript

#### SPDM 1.3 Example with Requester Context

**Request (MCTP + SPDM)**:
```
05 83 00 00 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F 80 81 82 83 84 85 86 87 88
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `83`: SPDM header (version 1.3, request code 0x3 for CHALLENGE)
- `00`: Param1 (slot ID 0)
- `00`: Param2 (NO_MEASUREMENT_SUMMARY_HASH)
- `61 62 63...80`: 32-byte random nonce
- `81 82 83...88`: 8-byte requester context

**Response (MCTP + SPDM)**:
```
05 03 00 01 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 81 82 83 84 85 86 87 88 [signature bytes...]
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `03`: SPDM header (version 1.3, response code 0x3 for CHALLENGE_AUTH)
- `00`: Param1 (slot ID 0)
- `01`: Param2 (slot mask 0x01, indicating slot 0 has a certificate)
- `00 01 02...1F`: 32-byte certificate chain hash
- `61 62 63...80`: 32-byte nonce (matching the request)
- `00 00 00...00`: 32-byte measurement summary hash (all zeros since not requested)
- `00 00`: Opaque data length (0)
- `81 82 83...88`: 8-byte requester context (matching the request)
- `[signature bytes...]`: Signature over the transcript

#### Error Response Example

**UNSUPPORTED_REQUEST Error Response (MCTP + SPDM)**:
```
05 7F 05 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `7F`: SPDM header (version 1.0, response code 0x7F for ERROR)
- `05`: Error code (UNSUPPORTED_REQUEST)
- `00`: Error data

## KEY_EXCHANGE Command

The KEY_EXCHANGE command is the first message in the SPDM Session Establishment Phase and is used to establish a secure session between the Requester and Responder. This command must be sent after the Authentication Phase is completed and initiates the process of creating an encrypted communication channel.

### Purpose and Functionality

The KEY_EXCHANGE command serves several critical purposes in the SPDM protocol:

1. **Session Establishment**: Initiates the creation of a secure session between Requester and Responder
2. **Key Exchange**: Performs a Diffie-Hellman key exchange to establish shared secret keys
3. **Session Parameters**: Negotiates session parameters such as heartbeat period
4. **Mutual Authentication**: Optionally requests mutual authentication from the Requester
5. **Measurement Verification**: Optionally includes a measurement summary hash for firmware integrity validation

### Message Format

#### KEY_EXCHANGE Request

The KEY_EXCHANGE request format varies slightly based on the SPDM version:

**SPDM 1.1 Format**:
```
+----------------+----------------+----------------+----------------+----------------+----------------+
| SPDM Header    | Param1         | Param2         | ReqSessionID   | Reserved       | RandomData     |
+----------------+----------------+----------------+----------------+----------------+----------------+
| ExchangeData   | OpaqueLength   | OpaqueData     |
+----------------+----------------+----------------+
```

**SPDM 1.2+ Format**:
```
+----------------+----------------+----------------+----------------+----------------+----------------+
| SPDM Header    | Param1         | Param2         | ReqSessionID   | SessionPolicy  | Reserved       |
+----------------+----------------+----------------+----------------+----------------+----------------+
| RandomData     | ExchangeData   | OpaqueLength   | OpaqueData     |
+----------------+----------------+----------------+----------------+
```

Detailed field breakdown:

| Field | Size (bytes) | Description |
|-------|--------------|-------------|
| SPDM Header | 1 | Bits 7-4: SPDM version<br>Bits 3-0: 0x4 (KEY_EXCHANGE) |
| Param1 | 1 | Measurement summary hash type |
| Param2 | 1 | Slot ID (0-7) to use for session establishment |
| ReqSessionID | 2 | Requester-assigned session ID |
| SessionPolicy | 1 | Session policy flags (SPDM 1.2+) |
| Reserved | 1 | Reserved, must be 0 |
| RandomData | 32 | Random data generated by the Requester |
| ExchangeData | Varies | Diffie-Hellman key exchange data<br>Size depends on the negotiated DHE algorithm |
| OpaqueLength | 2 | Length of the opaque data |
| OpaqueData | OpaqueLength | Opaque data (implementation-specific) |

**Measurement Summary Hash Type**:
| Value | Name | Description |
|-------|------|-------------|
| 0x00 | NO_MEASUREMENT_SUMMARY_HASH | No measurement summary hash requested |
| 0x01 | TCB_COMPONENT_MEASUREMENT_HASH | TCB component measurement hash requested |
| 0xFF | ALL_MEASUREMENTS_HASH | All measurements hash requested |

**Session Policy Flags (SPDM 1.2+)**:
| Bit | Name | Description |
|-----|------|-------------|
| 0 | TERMINATION_POLICY_RUNTIME_UPDATE | Session termination policy can be updated during runtime |
| 1 | EVENT_ALL_POLICY | Event notifications are enabled for all events |

**Important Notes**:
- The Slot ID must match one of the slots indicated in the DIGESTS response
- The ReqSessionID is assigned by the Requester and must be unique
- The RandomData must be a cryptographically random value to ensure session key uniqueness
- The ExchangeData contains the Requester's public key for the Diffie-Hellman key exchange

#### KEY_EXCHANGE_RSP Response

The KEY_EXCHANGE_RSP response format varies slightly based on the SPDM version:

```
+----------------+----------------+----------------+----------------+----------------+----------------+
| SPDM Header    | Param1         | Param2         | RspSessionID   | MutAuthReq     | ReqSlotID      |
+----------------+----------------+----------------+----------------+----------------+----------------+
| RandomData     | ExchangeData   | MeasurementHash| OpaqueLength   | OpaqueData     | Signature      |
+----------------+----------------+----------------+----------------+----------------+----------------+
| VerifyData     |
+----------------+
```

Detailed field breakdown:

| Field | Size (bytes) | Description |
|-------|--------------|-------------|
| SPDM Header | 1 | Bits 7-4: SPDM version<br>Bits 3-0: 0x4 (KEY_EXCHANGE_RSP) |
| Param1 | 1 | Heartbeat period |
| Param2 | 1 | Reserved, must be 0 |
| RspSessionID | 2 | Responder-assigned session ID |
| MutAuthReq | 1 | Mutual authentication requested flags |
| ReqSlotID | 1 | Requested slot ID for mutual authentication |
| RandomData | 32 | Random data generated by the Responder |
| ExchangeData | Varies | Diffie-Hellman key exchange data<br>Size depends on the negotiated DHE algorithm |
| MeasurementHash | H | Measurement summary hash (if requested)<br>Size H depends on the negotiated hash algorithm |
| OpaqueLength | 2 | Length of the opaque data |
| OpaqueData | OpaqueLength | Opaque data (implementation-specific) |
| Signature | Varies | Signature over the transcript<br>Size depends on the negotiated asymmetric algorithm |
| VerifyData | H | HMAC of the transcript using the derived handshake key<br>Size H depends on the negotiated hash algorithm |

**Mutual Authentication Requested Flags**:
| Value | Name | Description |
|-------|------|-------------|
| 0x01 | MUT_AUTH_REQUESTED | Basic mutual authentication requested |
| 0x02 | MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST | Mutual authentication with encapsulated request |
| 0x04 | MUT_AUTH_REQUESTED_WITH_GET_DIGESTS | Mutual authentication with GET_DIGESTS |

**Important Notes**:
- The RspSessionID is assigned by the Responder and combined with ReqSessionID to form the full session ID
- The Heartbeat period indicates how often heartbeat messages should be sent (in seconds)
- The MutAuthReq field indicates if and how mutual authentication is requested
- The ExchangeData contains the Responder's public key for the Diffie-Hellman key exchange
- The Signature is generated using the private key corresponding to the public key in the leaf certificate
- The VerifyData is an HMAC using the derived handshake key to verify key derivation success

### Key Derivation

The KEY_EXCHANGE command establishes a set of session keys through a Diffie-Hellman key exchange process. The key derivation process involves several steps:

1. **Shared Secret Calculation**:
   - Both parties perform a Diffie-Hellman key exchange to establish a shared secret
   - For ECDHE, this involves point multiplication of the peer's public key with the local private key
   - For FFDHE, this involves modular exponentiation of the peer's public value with the local private value

2. **Transcript Hash Calculation**:
   - A transcript hash (TH) is calculated over all messages exchanged up to this point
   - TH1 includes all messages up to and including the KEY_EXCHANGE_RSP (without the VerifyData)

3. **Key Derivation Function**:
   - The SPDM key schedule uses HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
   - The process follows NIST SP 800-56C and RFC 5869

4. **Session Keys Generated**:
   - **Handshake Secret**: Derived from the shared secret and TH1
   - **Handshake Key**: Used to generate and verify the VerifyData field
   - **Export Key**: Optional key that can be exported to higher layers
   - **Master Secret**: Derived from the handshake secret and TH1
   - **Encryption Key**: Used for session message encryption
   - **Decryption Key**: Used for session message decryption
   - **Request Finished Key**: Used for FINISH request verification
   - **Response Finished Key**: Used for FINISH response verification

**Key Derivation Contexts**:

SPDM 1.2+ uses specific context strings for key derivation:
- Requester context: "Requester-KEP-dmtf-spdm-v1.2"
- Responder context: "Responder-KEP-dmtf-spdm-v1.2"

**Key Derivation Sequence**:

```
+----------------+----------------+----------------+
| Shared Secret  | TH1            | HKDF-Extract   |
+----------------+----------------+----------------+
                                  |
                                  v
+----------------+----------------+----------------+
| Handshake      | Context        | HKDF-Expand    |
| Secret         |                |                |
+----------------+----------------+----------------+
                                  |
                                  v
+----------------+----------------+----------------+
| Handshake Key  | Export Key     | Master Secret  |
+----------------+----------------+----------------+
                                  |
                                  v
+----------------+----------------+----------------+
| Encryption Key | Decryption Key | Finished Keys  |
+----------------+----------------+----------------+
```

### Protocol Flow

1. **Requester Action**:
   - The Requester generates a random nonce and Diffie-Hellman key pair
   - The Requester assigns a unique ReqSessionID
   - The Requester constructs a KEY_EXCHANGE request with its public key
   - The Requester sends the KEY_EXCHANGE request to the Responder
   - The Requester waits for a KEY_EXCHANGE_RSP response

2. **Responder Action**:
   - The Responder receives the KEY_EXCHANGE request
   - The Responder validates the request format and parameters
   - The Responder generates a random nonce and Diffie-Hellman key pair
   - The Responder assigns a unique RspSessionID
   - The Responder calculates the shared secret using the Requester's public key
   - The Responder derives the session keys
   - The Responder calculates the measurement summary hash (if requested)
   - The Responder generates a signature over the transcript
   - The Responder calculates the VerifyData using the handshake key
   - The Responder constructs a KEY_EXCHANGE_RSP response
   - The Responder sends the KEY_EXCHANGE_RSP response to the Requester

3. **Session Establishment**:
   - The Requester receives the KEY_EXCHANGE_RSP response
   - The Requester validates the response format
   - The Requester calculates the shared secret using the Responder's public key
   - The Requester derives the session keys
   - The Requester verifies the signature using the Responder's public key
   - The Requester verifies the VerifyData using the derived handshake key
   - If all verifications pass, the session is partially established
   - The Requester proceeds to send a FINISH request to complete the session establishment

4. **Measurement Verification (Optional)**:
   - If a measurement summary hash was requested, the Requester validates it
   - The validation process depends on the specific measurement type and implementation

### State Management

The KEY_EXCHANGE command has significant effects on the SPDM state machine:

1. **State Verification**:
   - The Responder verifies that the Authentication Phase has been completed successfully
   - If not, the Responder returns an UNEXPECTED_REQUEST error
   - The Responder verifies that it has the KEY_EX_CAP capability
   - If not, the Responder returns an UNSUPPORTED_REQUEST error

2. **Session Creation**:
   - A new session context is created with a unique session ID
   - The session ID is formed by combining the ReqSessionID and RspSessionID
   - The session state is set to HANDSHAKING
   - The session keys are stored in the session context

3. **Transcript Management**:
   - The KEY_EXCHANGE request is added to the transcript
   - The KEY_EXCHANGE_RSP response (without VerifyData) is added to the transcript
   - The transcript hash TH1 is calculated and used for key derivation
   - A new transcript is started for the FINISH exchange

4. **Connection State**:
   - The connection state remains in AUTHENTICATED
   - The session state is set to HANDSHAKING until the FINISH exchange is completed

### Error Handling

The KEY_EXCHANGE command can encounter several error conditions:

1. **Invalid State**:
   - If the Authentication Phase has not been completed successfully
   - Response: ERROR with code UNEXPECTED_REQUEST (0x03)

2. **Unsupported Capability**:
   - If the Responder does not have the KEY_EX_CAP capability
   - Response: ERROR with code UNSUPPORTED_REQUEST (0x05)

3. **Invalid Slot ID**:
   - If the requested slot ID is not valid or does not contain a certificate
   - Response: ERROR with code INVALID_REQUEST (0x01)

4. **Invalid Measurement Hash Type**:
   - If the requested measurement hash type is not supported
   - Response: ERROR with code INVALID_REQUEST (0x01)

5. **Session Limit Reached**:
   - If the Responder cannot support more sessions
   - Response: ERROR with code INVALID_REQUEST (0x01)

6. **Key Exchange Failure**:
   - If the Diffie-Hellman key exchange fails
   - Response: ERROR with code UNSPECIFIED (0x04)

7. **Signature Generation Failure**:
   - If the Responder fails to generate a valid signature
   - Response: ERROR with code UNSPECIFIED (0x04)

8. **Busy State**:
   - If the Responder is temporarily unable to process the request
   - Response: ERROR with code BUSY (0x02)
   - The Requester should retry after a delay

### Retry Behavior

When the Requester receives an error response to a KEY_EXCHANGE request, it should follow these retry procedures:

1. **BUSY Error**:
   - Wait for the specified time (2^CT_Exponent μs) if provided
   - Retry the KEY_EXCHANGE request
   - Continue retrying until successful or retry limit is reached

2. **RESPONSE_NOT_READY Error**:
   - Send RESPOND_IF_READY with the same request code
   - Wait for the response or another error

3. **REQUEST_RESYNCH Error**:
   - Reset the local context
   - Restart the SPDM communication with GET_VERSION

4. **Other Errors**:
   - Terminate the SPDM communication
   - Report the error to higher layers

### Implementation Considerations

1. **Key Generation**:
   - The Diffie-Hellman key pair must be generated using a cryptographically secure random number generator
   - The key size must match the negotiated DHE algorithm
   - Ephemeral keys should be used for each session to provide forward secrecy

2. **Session ID Management**:
   - The Requester and Responder must ensure that session IDs are unique
   - Session IDs should be tracked to prevent reuse
   - The full session ID is the combination of ReqSessionID and RspSessionID

3. **Key Derivation**:
   - The key derivation function must follow the SPDM specification exactly
   - The transcript hash must include all messages in the correct order
   - The derived keys must be securely stored and managed

4. **Mutual Authentication**:
   - If mutual authentication is requested, the Requester must be prepared to authenticate itself
   - The mutual authentication method depends on the MutAuthReq field

5. **Security Implications**:
   - The KEY_EXCHANGE exchange establishes the security of the session
   - A failure in key generation, key exchange, or key derivation can lead to security vulnerabilities
   - Implementations should be carefully tested and validated

### KEY_EXCHANGE Examples

#### SPDM 1.1 Example

**Request (MCTP + SPDM)**:
```
05 E4 00 00 01 00 00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 [exchange data...] 00 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `E4`: SPDM header (version 1.1, request code 0x4 for KEY_EXCHANGE)
- `00`: Param1 (NO_MEASUREMENT_SUMMARY_HASH)
- `00`: Param2 (slot ID 0)
- `01 00`: ReqSessionID (0x0001)
- `00 00`: Reserved bytes
- `01 02 03...20`: 32-byte random data
- `[exchange data...]`: Diffie-Hellman exchange data (size depends on algorithm)
- `00 00`: Opaque data length (0)

**Response (MCTP + SPDM)**:
```
05 64 0A 00 02 00 00 00 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 [exchange data...] [measurement hash...] 00 00 [signature bytes...] [verify data bytes...]
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `64`: SPDM header (version 1.1, response code 0x64 for KEY_EXCHANGE_RSP)
- `0A`: Param1 (heartbeat period 10 seconds)
- `00`: Param2 (reserved)
- `02 00`: RspSessionID (0x0002)
- `00`: MutAuthReq (no mutual authentication requested)
- `00`: ReqSlotID (not used since no mutual authentication)
- `21 22 23...40`: 32-byte random data
- `[exchange data...]`: Diffie-Hellman exchange data (size depends on algorithm)
- `[measurement hash...]`: Measurement hash (if requested)
- `00 00`: Opaque data length (0)
- `[signature bytes...]`: Signature over the transcript
- `[verify data bytes...]`: HMAC over the transcript using the handshake key

#### SPDM 1.2 Example with Mutual Authentication

**Request (MCTP + SPDM)**:
```
05 E4 00 00 03 00 01 00 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F 60 [exchange data...] 00 05 6C 69 62 73 70 64 6D
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `E4`: SPDM header (version 1.2, request code 0x4 for KEY_EXCHANGE)
- `00`: Param1 (NO_MEASUREMENT_SUMMARY_HASH)
- `00`: Param2 (slot ID 0)
- `03 00`: ReqSessionID (0x0003)
- `01`: SessionPolicy (TERMINATION_POLICY_RUNTIME_UPDATE)
- `00`: Reserved byte
- `41 42 43...60`: 32-byte random data
- `[exchange data...]`: Diffie-Hellman exchange data (size depends on algorithm)
- `00 05`: Opaque data length (5 bytes)
- `6C 69 62 73 70 64 6D`: Opaque data ("libspdm")

**Response (MCTP + SPDM)**:
```
05 64 0A 00 04 00 01 01 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F 80 [exchange data...] [measurement hash...] 00 00 [signature bytes...] [verify data bytes...]
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `64`: SPDM header (version 1.2, response code 0x64 for KEY_EXCHANGE_RSP)
- `0A`: Param1 (heartbeat period 10 seconds)
- `00`: Param2 (reserved)
- `04 00`: RspSessionID (0x0004)
- `01`: MutAuthReq (basic mutual authentication requested)
- `01`: ReqSlotID (slot ID 1 requested for mutual authentication)
- `61 62 63...80`: 32-byte random data
- `[exchange data...]`: Diffie-Hellman exchange data (size depends on algorithm)
- `[measurement hash...]`: Measurement hash (if requested)
- `00 00`: Opaque data length (0)
- `[signature bytes...]`: Signature over the transcript
- `[verify data bytes...]`: HMAC over the transcript using the handshake key

#### Error Response Example

**UNSUPPORTED_REQUEST Error Response (MCTP + SPDM)**:
```
05 7F 05 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `7F`: SPDM header (version 1.0, response code 0x7F for ERROR)
- `05`: Error code (UNSUPPORTED_REQUEST)
- `00`: Error data

## FINISH Command

The FINISH command is the second and final message in the SPDM Session Establishment Phase and is used to complete the establishment of a secure session between the Requester and Responder. This command must be sent after KEY_EXCHANGE and finalizes the session by confirming the derived keys and optionally providing mutual authentication.

### Purpose and Functionality

The FINISH command serves several critical purposes in the SPDM protocol:

1. **Session Completion**: Finalizes the secure session establishment process
2. **Key Confirmation**: Confirms that both parties have derived the same session keys
3. **Mutual Authentication**: Optionally provides authentication of the Requester to the Responder
4. **Session State Transition**: Transitions the session to the established state
5. **Data Key Activation**: Activates the data protection keys for subsequent communication

### Message Format

#### FINISH Request

The FINISH request format is consistent across all SPDM versions:

```
+----------------+----------------+----------------+----------------+
| SPDM Header    | Param1         | Param2         | Signature      |
+----------------+----------------+----------------+----------------+
| VerifyData     |
+----------------+
```

Detailed field breakdown:

| Field | Size (bytes) | Description |
|-------|--------------|-------------|
| SPDM Header | 1 | Bits 7-4: SPDM version<br>Bits 3-0: 0x5 (FINISH) |
| Param1 | 1 | Bit 0: Signature included<br>Bits 1-7: Reserved, must be 0 |
| Param2 | 1 | Requester slot ID when signature is included<br>Otherwise, reserved (0) |
| Signature | Varies | Optional signature for mutual authentication<br>Only present if Param1 bit 0 is set<br>Size depends on the negotiated requester asymmetric algorithm |
| VerifyData | H | HMAC of the transcript using the Finished key<br>Size H depends on the negotiated hash algorithm |

**Important Notes**:
- The Signature is only included if mutual authentication was requested in the KEY_EXCHANGE_RSP
- The Requester slot ID indicates which certificate slot to use for mutual authentication
- The VerifyData is an HMAC using the Request Finished Key derived during KEY_EXCHANGE

#### FINISH_RSP Response

The FINISH_RSP response format is consistent across all SPDM versions:

```
+----------------+----------------+----------------+----------------+
| SPDM Header    | Param1         | Param2         | VerifyData     |
+----------------+----------------+----------------+----------------+
```

Detailed field breakdown:

| Field | Size (bytes) | Description |
|-------|--------------|-------------|
| SPDM Header | 1 | Bits 7-4: SPDM version<br>Bits 3-0: 0x5 (FINISH_RSP) |
| Param1 | 1 | Reserved, must be 0 |
| Param2 | 1 | Reserved, must be 0 |
| VerifyData | H | HMAC of the transcript using the Finished key<br>Size H depends on the negotiated hash algorithm<br>Only present if handshake in the clear is supported |

**Important Notes**:
- The VerifyData is only included if both parties support the HANDSHAKE_IN_THE_CLEAR capability
- If not included, the session is still established but without this final verification
- The VerifyData is an HMAC using the Response Finished Key derived during KEY_EXCHANGE

### Verify Data Generation

The VerifyData in both the FINISH request and FINISH_RSP response is a critical security element that confirms the key derivation process. The VerifyData is generated as follows:

1. **Transcript Hash Calculation**:
   - A transcript hash (TH2) is calculated over all messages exchanged up to this point
   - For the FINISH request, TH2 includes all messages up to and including the FINISH request (without the VerifyData)
   - For the FINISH_RSP response, TH2 includes all messages up to and including the FINISH_RSP response (without the VerifyData)

2. **HMAC Calculation**:
   - For the FINISH request, the VerifyData is calculated as HMAC(Request Finished Key, TH2)
   - For the FINISH_RSP response, the VerifyData is calculated as HMAC(Response Finished Key, TH2)

3. **Signature Generation (if required)**:
   - If mutual authentication is requested, the Requester generates a signature over the transcript
   - The signature context is "requester-finish signing"
   - The signature is generated using the Requester's private key corresponding to the certificate in the specified slot

### Protocol Flow

1. **Requester Action**:
   - The Requester calculates the transcript hash TH2
   - If mutual authentication was requested, the Requester generates a signature over the transcript
   - The Requester calculates the VerifyData using the Request Finished Key
   - The Requester constructs a FINISH request with the signature (if required) and VerifyData
   - The Requester sends the FINISH request to the Responder
   - The Requester waits for a FINISH_RSP response

2. **Responder Action**:
   - The Responder receives the FINISH request
   - The Responder validates the request format and parameters
   - If a signature is included, the Responder verifies it using the Requester's public key
   - The Responder verifies the VerifyData using the Request Finished Key
   - The Responder calculates its own transcript hash TH2
   - The Responder generates the session data keys
   - If handshake in the clear is supported, the Responder calculates its VerifyData using the Response Finished Key
   - The Responder constructs a FINISH_RSP response with the VerifyData (if required)
   - The Responder sends the FINISH_RSP response to the Requester

3. **Session Establishment Completion**:
   - The Requester receives the FINISH_RSP response
   - The Requester validates the response format
   - If VerifyData is included, the Requester verifies it using the Response Finished Key
   - The Requester generates the session data keys
   - The Requester transitions the session state to ESTABLISHED
   - The secure session is now fully established and ready for encrypted communication

### State Management

The FINISH command has significant effects on the SPDM state machine:

1. **State Verification**:
   - The Responder verifies that KEY_EXCHANGE has been completed successfully
   - If not, the Responder returns an UNEXPECTED_REQUEST error
   - The Responder verifies that the session is in the HANDSHAKING state
   - If not, the Responder returns an UNEXPECTED_REQUEST error

2. **Session State Transition**:
   - After successful processing of the FINISH request, the Responder transitions the session state to ESTABLISHED
   - After successful processing of the FINISH_RSP response, the Requester transitions the session state to ESTABLISHED

3. **Transcript Management**:
   - The FINISH request is added to the transcript
   - The FINISH_RSP response is added to the transcript
   - The transcript hash TH2 is calculated and used for key confirmation
   - After successful session establishment, the transcript is reset for the session

4. **Key Activation**:
   - The session data keys (encryption and decryption keys) are activated
   - All subsequent communication in the session will be encrypted using these keys

### Error Handling

The FINISH command can encounter several error conditions:

1. **Invalid State**:
   - If KEY_EXCHANGE has not been completed successfully
   - Response: ERROR with code UNEXPECTED_REQUEST (0x03)

2. **Invalid Session ID**:
   - If the session ID does not match a valid session in the HANDSHAKING state
   - Response: ERROR with code INVALID_REQUEST (0x01)

3. **Signature Verification Failure**:
   - If mutual authentication was requested and the signature verification fails
   - Response: ERROR with code DECRYPT_ERROR (0x0B)

4. **VerifyData Verification Failure**:
   - If the VerifyData verification fails
   - Response: ERROR with code DECRYPT_ERROR (0x0B)

5. **Key Derivation Failure**:
   - If the session data key derivation fails
   - Response: ERROR with code UNSPECIFIED (0x04)

6. **Busy State**:
   - If the Responder is temporarily unable to process the request
   - Response: ERROR with code BUSY (0x02)
   - The Requester should retry after a delay

### Retry Behavior

When the Requester receives an error response to a FINISH request, it should follow these retry procedures:

1. **BUSY Error**:
   - Wait for the specified time (2^CT_Exponent μs) if provided
   - Retry the FINISH request
   - Continue retrying until successful or retry limit is reached

2. **RESPONSE_NOT_READY Error**:
   - Send RESPOND_IF_READY with the same request code
   - Wait for the response or another error

3. **REQUEST_RESYNCH Error**:
   - Reset the local context
   - Restart the SPDM communication with GET_VERSION

4. **DECRYPT_ERROR or Other Errors**:
   - Terminate the session
   - Optionally attempt to establish a new session
   - Report the error to higher layers

### Implementation Considerations

1. **Mutual Authentication**:
   - If mutual authentication is requested, the Requester must have a valid certificate and private key
   - The Requester must be able to generate a signature over the transcript
   - The Responder must verify the signature using the Requester's public key

2. **VerifyData Calculation**:
   - The VerifyData calculation must use the correct Finished Key (Request or Response)
   - The transcript hash must include all messages in the correct order
   - The HMAC algorithm must match the negotiated hash algorithm

3. **Session Key Management**:
   - The session data keys must be securely stored and managed
   - The session keys should be unique for each session
   - The session keys should be protected from unauthorized access

4. **Handshake in the Clear**:
   - If handshake in the clear is supported, the VerifyData in the FINISH_RSP response must be included
   - If handshake in the clear is not supported, the VerifyData in the FINISH_RSP response must be omitted

5. **Security Implications**:
   - The FINISH exchange completes the session establishment
   - A failure in signature verification, VerifyData verification, or key derivation can lead to security vulnerabilities
   - Implementations should be carefully tested and validated

### FINISH Examples

#### SPDM 1.1 Example without Mutual Authentication

**Request (MCTP + SPDM)**:
```
05 E5 00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `E5`: SPDM header (version 1.1, request code 0x5 for FINISH)
- `00`: Param1 (no signature included)
- `00`: Param2 (reserved)
- `01 02 03...20`: 32-byte VerifyData (HMAC over the transcript)

**Response (MCTP + SPDM)**:
```
05 65 00 00 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `65`: SPDM header (version 1.1, response code 0x65 for FINISH_RSP)
- `00`: Param1 (reserved)
- `00`: Param2 (reserved)
- `21 22 23...40`: 32-byte VerifyData (HMAC over the transcript)

#### SPDM 1.2 Example with Mutual Authentication

**Request (MCTP + SPDM)**:
```
05 E5 01 01 [signature bytes...] 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F 60
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `E5`: SPDM header (version 1.2, request code 0x5 for FINISH)
- `01`: Param1 (signature included)
- `01`: Param2 (slot ID 1)
- `[signature bytes...]`: Signature over the transcript (size depends on algorithm)
- `41 42 43...60`: 32-byte VerifyData (HMAC over the transcript)

**Response (MCTP + SPDM)**:
```
05 65 00 00 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F 80
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `65`: SPDM header (version 1.2, response code 0x65 for FINISH_RSP)
- `00`: Param1 (reserved)
- `00`: Param2 (reserved)
- `61 62 63...80`: 32-byte VerifyData (HMAC over the transcript)

#### Error Response Example

**DECRYPT_ERROR Error Response (MCTP + SPDM)**:
```
05 7F 0B 00
```

Breakdown:
- `05`: MCTP header (message type 0x05 for SPDM)
- `7F`: SPDM header (version 1.0, response code 0x7F for ERROR)
- `0B`: Error code (DECRYPT_ERROR)
- `00`: Error data

## Decoding SPDM over MCTP Messages

To decode SPDM over MCTP messages:

1. **Extract MCTP Header**:
   - First byte contains the MCTP message type (0x05 for SPDM)

2. **Extract SPDM Header**:
   - Second byte contains the SPDM version (bits 7-4) and request/response code (bits 3-0)

3. **Parse Message Body**:
   - Based on the request/response code, parse the message body according to the SPDM specification

4. **For Secured Messages**:
   - Extract the session ID (4 bytes)
   - Extract the sequence number (2 bytes)
   - Extract the length (2 bytes)
   - Decrypt the encrypted data using the session keys
   - Verify the MAC

## References

1. DMTF DSP0274: Security Protocol and Data Model (SPDM) Specification
2. DMTF DSP0275: Security Protocol and Data Model (SPDM) over MCTP Binding Specification
3. DMTF DSP0276: Secured Messages using SPDM over MCTP Binding Specification
4. DMTF DSP0236: Management Component Transport Protocol (MCTP) Base Specification
5. DMTF DSP0277: Secured Messages using SPDM Specification

## Decoding SPDM over MCTP Messages

To decode SPDM over MCTP messages:

1. **Extract MCTP Header**:
   - First byte contains the MCTP message type (0x05 for SPDM)

2. **Extract SPDM Header**:
   - Second byte contains the SPDM version (bits 7-4) and request/response code (bits 3-0)

3. **Parse Message Body**:
   - Based on the request/response code, parse the message body according to the SPDM specification

4. **For Secured Messages**:
   - Extract the session ID (4 bytes)
   - Extract the sequence number (2 bytes)
   - Extract the length (2 bytes)
   - Decrypt the encrypted data using the session keys
   - Verify the MAC

Example decoding of a GET_VERSION request:
```
05 84 00 00 00 00
```

1. MCTP Header: `05` (SPDM message type)
2. SPDM Header: `84` (version 1.0, request code 0x4 for GET_VERSION)
3. Reserved bytes: `00 00 00 00`

## References

1. DMTF DSP0274: Security Protocol and Data Model (SPDM) Specification
2. DMTF DSP0275: Security Protocol and Data Model (SPDM) over MCTP Binding Specification
3. DMTF DSP0276: Secured Messages using SPDM over MCTP Binding Specification
4. DMTF DSP0236: Management Component Transport Protocol (MCTP) Base Specification
5. DMTF DSP0277: Secured Messages using SPDM Specification
