// In your includes/base_kernel.h:

// ... (existing extern declarations) ...

extern void net_ne2000_handler_c(void); // Declare the network interrupt handler

// Utility for int to hex string (used by net_ne2000_extension.c)
void int_to_hex_str(uint16_t val, char* buf); // Declare this utility function
