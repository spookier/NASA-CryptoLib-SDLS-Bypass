# CVE-2025-46673 Proof of Concept

**SDLS Bypass via Uninitialized Security Associations**

## Overview

NASA's CryptoLib fails to validate Security Association state before use, allowing attackers to bypass SDLS encryption and authentication by using uninitialized SA slots (17-63).

**[This PoC](https://github.com/spookier/NASA-CryptoLib-SDLS-Bypass/blob/main/PoC.cpp) demonstrates how the SDLS bypass works (no RF hardware required)**



**Can escalate to:** Complete spacecraft hijacking (key management exploit -> operator lockout -> permanent takeover)

---

#### Compilation Instructions:

**Linux/Mac:**
```
# Using g++
g++ -std=c++11 poc.cpp -o poc

# Using clang++
clang++ -std=c++11 poc.cpp -o poc
```

**Windows (Command Prompt):**
```
# Using MSVC
cl /EHsc poc.cpp

# Using MinGW
g++ -std=c++11 poc.cpp -o poc.exe
```


---

## Disclaimer

⚠️ **Educational purposes only**  

Non-functional PoC demonstrating vulnerability logic. No RF transmission capabilities.

Do not use against systems you don't own or have permission to test.


---


## References

- [CVE-2025-46673](https://nvd.nist.gov/vuln/detail/CVE-2025-46673)
- [NASA CryptoLib](https://github.com/nasa/CryptoLib)
