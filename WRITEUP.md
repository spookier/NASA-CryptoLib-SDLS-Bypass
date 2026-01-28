
##  [CVE-2025-46673](https://nvd.nist.gov/vuln/detail/CVE-2025-46675) - Writeup for SDLS Bypass via Uninitialized Security Associations

### 1 - Understanding the Setup

#### The Normal Flow (How it should work)

On the spacecraft, there's an array of structures called **"Security Associations"** (also called **SAs**/**SA**)

At a high level, this structure acts as a **lookup table entry**. It tells the spacecraft exactly how to handle one specific "conversation" (communication session) with ground control.

The structure includes things like:
- Which encryption method to use (AES-GCM, AES-CBC, etc...)
- Which secret key to use for that encryption
- Whether to add a security signature/authentication tag (MAC)
- Other settings

**Source:** [`struct SecurityAssociation`](https://github.com/nasa/CryptoLib/blob/2a237a3fa46822c2c339a0ab0b152c8697aa5093/include/crypto_structs.h#L67)
```c
SecurityAssociation_t sa[64];  // 64 slots for different crypto configurations

struct SecurityAssociation
{
    int sa_state;      // Is this SA ready to use?
                       // Values: SA_OPERATIONAL, SA_NONE, SA_UNKEYED, etc.
    
    int est;           // Encryption
				       // 0 = no encryption, 1 = AES-GCM, 2 = AES-CBC, etc.
      
    int ast;           // Authentication Type  
                       // 0 = no authentication, 1 = AES-CMAC, 2 = HMAC-SHA, etc.

    // ... other crypto configuration fields
};
```

What `est` / `ast` does:  These tell the system whether to encrypt the data, authenticate (sign) it, or both.

Not every communication session is encrypted because spacecraft hardware is often extremely constrained, so you need to be very specific about how you process data to save battery and CPU power:

- **`est = 0, ast = 0`**: No encryption at all = "Clear Mode" (plaintext, used for testing)
- **`est = 0, ast = 1`**: Only authentication = Verify integrity, but don't encrypt
- **`est = 1, ast = 0`**: Only encryption = Hide data, but don't verify sender
- **`est = 1, ast = 1`**: Both = Full protection (this is the secure mode)

**Examples of why we need different modes:**
- **Telemetry (spacecraft -> ground):** Often only needs authentication (`ast=1, est=0`) because the data isn't secret, but you want to make sure it hasn't been tampered with
- **Telecommands (ground -> spacecraft):** Usually needs both (`est=1, ast=1`) because commands are sensitive and must be verified
- **Testing/Development:** Sometimes uses clear mode (`est=0, ast=0`) to debug without crypto overhead


#### The Frame Structure

^521d3e

Every command sent to the spacecraft is wrapped in a **TC (Telecommand) Transfer Frame**
```
┌──────────────┬─────────────────┬──────────────┬─────────────────┐
│Primary Header│ Security Header │   Payload    │ Security Trailer│
│  (5 bytes)   │  (SPI + other)  │  (command)   │    (MAC tag)    │
└──────────────┴─────────────────┴──────────────┴─────────────────┘
       ▲                ▲               ▲               ▲
       │                │               │               │
   Spacecraft ID    Which SA to    The actual      Proves it's
   and metadata     use (0-63)     command         authentic
```

**The SPI (Security Parameter Index)** is the key field here.
It's just a number that says "use SA slot N for this frame"

So when a frame arrives:
1. Extract the SPI from the Security Header
2. Look up `sa[SPI]` to get the crypto settings
3. Apply the encryption/authentication based on that SA's `est` and `ast` values
4. If everything is ok, execute the command

---
### 2 - The Vulnerability

#### What NASA Did Wrong (The Bug)

```c
// Step 1: Static Allocation
SecurityAssociation_t sa[64];  // 64 slots allocated, contains GARBAGE

// Step 2: Clean Memory (replace the garbage memory with 0)
memset(sa, 0, sizeof(SecurityAssociation_t) * 64);

// At this point, all 64 SAs now contain ALL ZEROS

// Step 3: Configuration 
for (int i = 0; i < 17; i++) {
    sa[i].sa_state = SA_OPERATIONAL;      // Mark as "ready to use"
    sa[i].est = 1;                        // Enable encryption
    sa[i].ast = 1;                        // Enable authentication
    sa[i].key = load_real_key(i);         // Load NASA's secret key
}

```

**The Problem:**

- The `for loop` only configures SAs 0-16 (17 total slots)
- SAs 17-63 (remaining 47 slots) were left "empty", just zeros from the `memset()`

```c
// The 47 remaining slots look like this:
sa[17..63].sa_state = 0 // ( 0 means SA_NONE = not operational)
sa[17..63].est = 0
sa[17..63].ast = 0
sa[17..63].key = {0,0,0,...}
```


### 2.1 - The Vulnerable Code Path

When [[#^521d3e|a frame]] arrives at the spacecraft, the system would use any slot it was told to use
It never checked if the slot was actually marked as ready (SA_OPERATIONAL) or not

Here's what happens:

```c
// Step 1: Extract SPI from the incoming frame
// SPI = "Security Parameter Index" = which SA slot to use
uint16_t spi = extract_spi_from_frame(frame);


// Step 2: Look up the SA using the SPI as an array index
SecurityAssociation_t *sa_ptr = &sa[spi];

// If spi=44, we access sa[44] (which is uninitialized!)

// Step 3: Determine what crypto mode to use
// [!] THIS IS THE CRITICAL BUG
if (sa_ptr->est == 0 && sa_ptr->ast == 0)
{
    // "Oh, est=0 and ast=0? That means Clear Mode!"
    service_type = SA_PLAINTEXT;  // BYPASS ALL CRYPTO
    // Process the frame without ANY encryption or authentication!
}
else
{
    // Apply encryption/authentication based on est/ast values
}
```


**Why This Is Vulnerable:**

1. Attacker sends frame with `SPI=44` (or any value between 17-63)
2. Spacecraft accesses `sa[44]` which has `est=0 ast=0` (all zeros, which means no encryption)
3. Code **misinterprets** this as "intentional Clear Mode"
4. Frame is processed without any cryptographic verification
5. Command executes on spacecraft as if it came from legitimate ground control

---
### 3- Root Cause Analysis

#### The Design Flaws

The vulnerability comes from **two critical mistakes** in CryptoLib

Mistake #1 - A missing security check to see if the state was initialized
```c
// WRONG: Relying on field values instead of an explicit state
if (sa_ptr->est == 0 && sa_ptr->ast == 0)
    service_type = SA_PLAINTEXT;

// RIGHT: Check if the SA was intentionally configured first
if (sa_ptr->sa_state != SA_OPERATIONAL)
    return ERROR;
```

The code assumes that `est=0, ast=0` means "intentional plaintext mode for testing"

But it **never checks** if that SA was deliberately configured or just happens to be zeros from `memset()`


Mistake #2 - Incomplete resource initialization
```c
// Allocate 64 slots
SecurityAssociation_t sa[64];

// Zero them all out
memset(sa, 0, sizeof(SecurityAssociation_t) * 64);

// Only initialize 17 of them
for (int i = 0; i < 17; i++) {
    sa[i].sa_state = SA_OPERATIONAL;
    sa[i].est = 1;
    sa[i].ast = 1;
    // ... crypto setup
}

// Problem: sa[17-63] remain in "zeroed but not configured" state
// They're accessible but invalid
```

---
### 4 - Impact Assessment

#### What Can an Attacker Do?

**Direct Impact: The nullification of the SDLS protocol**
```text
Attack: Send frame with SPI=44 (or any uninitialized SA)
Result: All cryptographic protection bypassed
Impact:
  - No encryption         = Attacker can send commands in plaintext
  - No authentication     = No verification of sender identity
  - No integrity checking = Commands accepted without validation
```

This is critical because it breaks the entire security model. SDLS is supposed to be the only layer protecting spacecraft communications

Once bypassed, an attacker can send **any command** the spacecraft supports:
- Activate/deactivate systems
- Change orbital parameters (fire thrusters)
- Corrupt or delete mission data
- Reconfigure instruments
- Disable safety protocols
- Reboot loop (Denial of Service)

#### Real-World Scenarios (APT / Intelligence Operations)

**Scenario 1: Missile Warning Satellite (DSP/SBIRS)**
- **The Command:** `ALERT_THRESHOLD_ADJUST INFRARED_PLUME_DETECTION +500%`
- **The Action:** Increase detection threshold so satellite only alerts on unrealistically large heat signatures
- **The Consequence:** Enemy launches submarine ballistic missile. Satellite fails to detect launch (heat signature below new threshold). Missile detected only by ground radar with 4 minute warning instead of 15 minute warning from satellite. Enemy mobile radar systems appear as civilian trucks.

**Scenario 2: SIGINT Satellite (Communications Intelligence)
- **The Command:** `TRANSPONDER_CONFIG REDIRECT FREQ=XXX.XX POLARIZATION=LHCP`
- **The Action:** Reconfigure communications relay to a different ground station instead of legitimate one. Can also force satellite to switch all communications to a crypto with known weaknesses.
- **The Consequence:** Encrypted tactical communications are routed to the enemy first before being forwarded to legitimate operators. Adversary captures encryption keys during key distribution phase or simply instantly decrypted.

**Scenario 3: Navigation Augmentation (SBAS/WAAS)**
- **The Command:** `BROADCAST_CORRECTION_DATA [MALICIOUS_EPHEMERIS]`
- **The Action:** Upload false GPS correction data to satellite
- **The Consequence:** Precision guided munitions targeting coordinates shifted by 50+ meters. Military drone strike hits civilian hospital instead of target. Appears as satellite malfunction, database corruption, or GPS atmospheric interference. No evidence of external attack, just "technical failure".


---

### 5 - Exploitation Path

#### 5.1 - Prerequisites - What the attacker needs


**1. Hardware (Radio Equipment)**
- **Software Defined Radio (SDR)**: A special radio that you can program
    - Examples: HackRF One, USRP, or RTL-SDR
    - Needs to transmit in the satellite's frequency range
- **Antenna**: A dish or directional antenna to focus the signal
    - Needs to point at the satellite in the sky
    - Bigger antenna = stronger signal reaches farther
- **GPS Module**: To know exactly what time it is
    - Satellites move fast, timing matters
    - USB GPS dongles (~$20-50)

**2. Target Information (Publicly Available)**
You need to know where the satellite is and how to talk to it:
- **Uplink Frequency**: What "channel" the satellite listens on
    - Often published for civilian/research satellites
    - Example: 2.025 GHz for some weather satellites
- **Spacecraft ID**: The satellite's unique number
    - Can be found by listening to its downlink (broadcast data)
    - The satellite constantly sends telemetry that includes its ID
- **Orbital Data (TLE - Two-Line Elements)**: Where the satellite is in space
    - Free from websites like Space-Track.org or Celestrak.com
    - Updated daily, tells you where it is

**3. Technical Knowledge**
- Understanding of CCSDS protocol (the "language" satellites speak)
    - This is a public standard, anyone can read the documentation
    - Similar to knowing HTTP for web servers
- Basic radio communication concepts
    - How to modulate a signal (turn data into radio waves)
    - Similar difficulty to setting up a ham radio

**Target Requirements:**
- Satellite running vulnerable CryptoLib v1.3.0 or v1.3.1
- SDLS enabled (most NASA/space agency satellites)
- No additional security layers

---
#### 5.2 - Attack Steps

**Phase 1: Find the Satellite's ID**
- Pick a target
- Download its info from public website
- Calculate when your antenna can "see" the satellite
	- (example: "Next pass: Today at 14:23 for 8 minutes") 
- Listen to its broadcast data using the SDR
- Extract the spacecraft ID from the telemetry

**Phase 2: Build the Attack Frame**
The attack frame has 3 parts:
1. **Primary Header**: Satellite's ID + communication channel + message length
2. **Security Header**: Use SPI at slot 44 (UNINITIALIZED!) + random IV
3. **The Command**: The command we want to send (example: NOOP test command)

Combine everything into one single frame

**Phase 3: Send It**
- Configure SDR with satellite's uplink frequency
- Wait for satellite to pass overhead
- Transmit the frame
- Listen for response

If successful: Command executes without any crypto verification

##### Why This Works

```
Normal Frame (SPI=5):
Satellite checks SA[5] -> est=1, ast=1 = Needs encryption+auth = Rejects request

Attack Frame (SPI=44):
Satellite checks SA[44] -> est=0, ast=0 -> "Test Mode!" -> Accepts without crypto!
```


---

#### 6 - Proof of Concept

I've developed a C++ proof of concept that simulates NASA CryptoLib vulnerable 
initialization and frame processing code. The PoC demonstrates exactly how the 
bug works without requiring any satellite hardware.

**Full PoC available at:** https://github.com/spookier/NASA-CryptoLib-SDLS-Bypass

---

#### 7 - Mitigation and Remediation

#### Official Patch (CryptoLib v1.3.2+)

NASA released a fix that adds the missing state validation:
```c
// Added check before processing frame
if (sa_ptr->sa_state != SA_OPERATIONAL)
{
    return CRYPTO_LIB_ERR_INVALID_SA_STATE;
}

// Now only properly configured SAs (0-16) can be used
// Uninitialized SAs (17-63) are rejected
```

**The fix is simple:** One `if` statement checking `sa_state` before checking `est/ast` values.
