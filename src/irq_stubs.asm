; In your src/irq_stubs.asm:

; ... (existing IRQ_COMMON macro and global irq0, irq1) ...

global irq3
irq3:
    IRQ_COMMON 0x23 ; IRQ3, which maps to 0x23 after PIC remap
    call net_ne2000_handler_c ; Call the NE2000 C handler

; ... (rest of the ISR definitions) ...
