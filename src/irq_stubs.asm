; In the user's src/irq_stubs.asm:

; Find the existing global IRQ declarations (e.g., irq0, irq1) and add:
global irq3
irq3:
    IRQ_COMMON 0x23
    call net_ne2000_handler_c
