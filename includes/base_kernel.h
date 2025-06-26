// In the user's includes/base_kernel.h:

// Find the section with extern declarations for interrupt handlers and add:
extern void net_ne2000_handler_c(void);

// Find a suitable place for utility function declarations (if not already present) and add:
void int_to_hex_str(uint16_t val, char* buf);
