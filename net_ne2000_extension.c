#include <stdint.h>
#include <stddef.h>
#include "base_kernel.h"

#define NE2000_BASE_PORT    0x300
#define NE2000_IRQ          3

#define NE_CR       0x00
#define NE_CLDA0    0x01
#define NE_CLDA1    0x02
#define NE_BNRY     0x03
#define NE_TPSR     0x04
#define NE_TBCR0    0x05
#define NE_TBCR1    0x06
#define NE_ISR      0x07
#define NE_RBCR0    0x08
#define NE_RBCR1    0x09
#define NE_RSAR0    0x08
#define NE_RSAR1    0x09
#define NE_RCR      0x0C
#define NE_TCR      0x0D
#define NE_DCR      0x0E
#define NE_IMR      0x0F

#define NE_PAR0     0x01
#define NE_MAR0     0x08
#define NE_CURR     0x07

#define NE_PSTART   0x01
#define NE_PSTOP    0x02

#define NE_CR_STOP      0x01
#define NE_CR_START     0x02
#define NE_CR_TXP       0x04
#define NE_CR_RD0       0x08
#define NE_CR_RD1       0x10
#define NE_CR_NO_DMA    0x00
#define NE_CR_PS0       0x20
#define NE_CR_PS1       0x40
#define NE_CR_PS_PAGE0  0x00
#define NE_CR_PS_PAGE1  0x40
#define NE_CR_PS_PAGE2  0x80

#define NE_ISR_PRX      0x01
#define NE_ISR_PTX      0x02
#define NE_ISR_RXE      0x04
#define NE_ISR_TXE      0x08
#define NE_ISR_OVW      0x10
#define NE_ISR_CNT      0x20
#define NE_ISR_RDC      0x40
#define NE_ISR_RST      0x80

#define NE_START_PAGE 0x40
#define NE_STOP_PAGE  0x60
#define NE_TX_PAGE    0x60

#define ETH_MAC_LEN         6
#define ETH_TYPE_LEN        2
#define ETH_HEADER_LEN      (ETH_MAC_LEN * 2 + ETH_TYPE_LEN)
#define ETH_MAX_FRAME_LEN   1518
#define ETH_MIN_FRAME_LEN   64

#define ETH_TYPE_CUSTOM 0x8888

static int ne2000_ext_id = -1;
static uint8_t mac_address[ETH_MAC_LEN];
static uint16_t io_base = NE2000_BASE_PORT;
static volatile uint8_t current_rx_page = NE_START_PAGE + 1;

static inline void ne_set_cr(uint8_t cmd) {
    outb(io_base + NE_CR, cmd);
}

static inline void ne_select_page(uint8_t page) {
    ne_set_cr((inb(io_base + NE_CR) & 0x3F) | (page << 6));
}

static inline void ne_write_reg(uint8_t reg, uint8_t val) {
    outb(io_base + reg, val);
}

static inline uint8_t ne_read_reg(uint8_t reg) {
    return inb(io_base + reg);
}

static void ne_rdm_read(uint16_t nic_addr, uint8_t *buffer, uint16_t len) {
    ne_set_cr(NE_CR_STOP | NE_CR_NO_DMA);
    ne_select_page(0);

    ne_write_reg(NE_RBCR0, (uint8_t)(len & 0xFF));
    ne_write_reg(NE_RBCR1, (uint8_t)(len >> 8));
    ne_write_reg(NE_RSAR0, (uint8_t)(nic_addr & 0xFF));
    ne_write_reg(NE_RSAR1, (uint8_t)(nic_addr >> 8));

    ne_set_cr(NE_CR_RD0 | NE_CR_START);

    while (!(ne_read_reg(NE_ISR) & NE_ISR_RDC));
    ne_write_reg(NE_ISR, NE_ISR_RDC);

    for (uint16_t i = 0; i < len; i++) {
        buffer[i] = inb(io_base + 0x10);
    }
}

static void ne_rdm_write(uint16_t nic_addr, const uint8_t *buffer, uint16_t len) {
    ne_set_cr(NE_CR_STOP | NE_CR_NO_DMA);
    ne_select_page(0);

    ne_write_reg(NE_RBCR0, (uint8_t)(len & 0xFF));
    ne_write_reg(NE_RBCR1, (uint8_t)(len >> 8));
    ne_write_reg(NE_RSAR0, (uint8_t)(nic_addr & 0xFF));
    ne_write_reg(NE_RSAR1, (uint8_t)(nic_addr >> 8));

    ne_set_cr(NE_CR_RD1 | NE_CR_START);

    for (uint16_t i = 0; i < len; i++) {
        outb(io_base + 0x10, buffer[i]);
    }

    while (!(ne_read_reg(NE_ISR) & NE_ISR_RDC));
    ne_write_reg(NE_ISR, NE_ISR_RDC);
}

void net_ne2000_handler_c() {
    uint8_t isr_status = ne_read_reg(NE_ISR);
    ne_write_reg(NE_ISR, isr_status);

    if (isr_status & NE_ISR_PRX) {
        terminal_writestring("NET: Packet Received!\n");

        ne_select_page(1);
        uint8_t current = ne_read_reg(NE_CURR);
        ne_select_page(0);

        while (ne_read_reg(NE_BNRY) != current) {
            uint8_t rx_header[4];
            ne_rdm_read((uint16_t)ne_read_reg(NE_BNRY) << 8, rx_header, 4);

            uint16_t packet_size = rx_header[2] | (rx_header[3] << 8);

            uint8_t *packet_buffer = (uint8_t*)kmalloc(packet_size);
            if (packet_buffer) {
                ne_rdm_read(((uint16_t)ne_read_reg(NE_BNRY) << 8) + 4, packet_buffer, packet_size - 4);

                terminal_writestring("NET: Received (");
                char num_str[10];
                int i = 0; uint16_t temp_size = packet_size; if (temp_size == 0) { num_str[0] = '0'; i = 1; } else { while (temp_size > 0) { num_str[i++] = (temp_size % 10) + '0'; temp_size /= 10; } } num_str[i] = '\0'; for (int start = 0, end = i - 1; start < end; start++, end--) { char tmp = num_str[start]; num_str[start] = num_str[end]; num_str[end] = tmp; }
                terminal_writestring(num_str);
                terminal_writestring(" bytes): ");

                for (int p = 0; p < (packet_size > 32 ? 32 : packet_size); p++) {
                    char hex_char_h = "0123456789ABCDEF"[(packet_buffer[p] >> 4) & 0xF];
                    char hex_char_l = "0123456789ABCDEF"[packet_buffer[p] & 0xF];
                    terminal_putchar(hex_char_h);
                    terminal_putchar(hex_char_l);
                    terminal_putchar(' ');
                }
                terminal_writestring("\n");

                uint16_t ether_type = (packet_buffer[12] << 8) | packet_buffer[13];
                if (ether_type == ETH_TYPE_CUSTOM) {
                     terminal_writestring("NET: Custom message: ");
                     for (int p = ETH_HEADER_LEN; p < packet_size - 4; p++) {
                         if (packet_buffer[p] >= 32 && packet_buffer[p] <= 126) {
                             terminal_putchar(packet_buffer[p]);
                         } else {
                             terminal_putchar('.');
                         }
                     }
                     terminal_writestring("\n");
                }
                kfree(packet_buffer);
            }

            uint8_t next_page_to_advance = rx_header[1];

            ne_write_reg(NE_BNRY, next_page_to_advance);
            ne_select_page(1);
            ne_write_reg(NE_CURR, next_page_to_advance);
            ne_select_page(0);
        }
    }

    if (isr_status & NE_ISR_PTX) {
        terminal_writestring("NET: Packet Transmitted!\n");
    }

    outb(0x20, 0x20);
}

static uint8_t hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static int parse_mac_address(const char* mac_str, uint8_t* mac_out) {
    if (strlen(mac_str) != 17) return -1;

    for (int i = 0; i < ETH_MAC_LEN; i++) {
        mac_out[i] = (hex_to_int(mac_str[i*3]) << 4) | hex_to_int(mac_str[i*3 + 1]);
        if (i < ETH_MAC_LEN - 1 && mac_str[i*3 + 2] != ':') return -1;
    }
    return 0;
}

void int_to_hex_str(uint16_t val, char* buf) {
    int i = 0;
    if (val == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return;
    }
    char tmp[5];
    int k = 0;
    while(val > 0) {
        uint8_t rem = val % 16;
        if (rem < 10) tmp[k++] = rem + '0';
        else tmp[k++] = rem + 'A' - 10;
        val /= 16;
    }
    tmp[k] = '\0';
    for (int j = 0; j < k; j++) {
        buf[j] = tmp[k - 1 - j];
    }
    buf[k] = '\0';
}

void cmd_net_info(const char* args) {
    terminal_writestring("NET: NE2000 Adapter Info\n");
    terminal_writestring("     Base Port: 0x");
    char hex_str[5];
    int_to_hex_str(io_base, hex_str);
    terminal_writestring(hex_str);
    terminal_writestring("\n     MAC Address: ");
    for (int i = 0; i < ETH_MAC_LEN; i++) {
        char hex_char_h = "0123456789ABCDEF"[(mac_address[i] >> 4) & 0xF];
        char hex_char_l = "0123456789ABCDEF"[mac_address[i] & 0xF];
        terminal_putchar(hex_char_h);
        terminal_putchar(hex_char_l);
        if (i < ETH_MAC_LEN - 1) {
            terminal_putchar(':');
        }
    }
    terminal_writestring("\n");
}

void cmd_net_send(const char* args) {
    if (strlen(args) < 18) {
        terminal_writestring("Usage: net_send <dest_mac_addr> <message>\n");
        return;
    }

    uint8_t dest_mac[ETH_MAC_LEN];
    char mac_str[18];
    for (int i = 0; i < 17; i++) mac_str[i] = args[i];
    mac_str[17] = '\0';

    if (parse_mac_address(mac_str, dest_mac) != 0) {
        terminal_writestring("NET: Invalid destination MAC address format.\n");
        return;
    }

    const char* message = args + 18;
    size_t message_len = strlen(message);
    if (message_len == 0) {
        terminal_writestring("NET: Message cannot be empty.\n");
        return;
    }

    uint16_t data_len = message_len;
    uint16_t total_len = ETH_HEADER_LEN + data_len;
    if (total_len < ETH_MIN_FRAME_LEN) {
        total_len = ETH_MIN_FRAME_LEN;
    }

    uint8_t *frame_buffer = (uint8_t*)kmalloc(total_len);
    if (!frame_buffer) {
        terminal_writestring("NET: Failed to allocate frame buffer.\n");
        return;
    }

    for (int i = 0; i < ETH_MAC_LEN; i++) frame_buffer[i] = dest_mac[i];
    for (int i = 0; i < ETH_MAC_LEN; i++) frame_buffer[ETH_MAC_LEN + i] = mac_address[i];
    frame_buffer[12] = (ETH_TYPE_CUSTOM >> 8) & 0xFF;
    frame_buffer[13] = ETH_TYPE_CUSTOM & 0xFF;

    for (size_t i = 0; i < message_len; i++) {
        frame_buffer[ETH_HEADER_LEN + i] = message[i];
    }

    for (uint16_t i = ETH_HEADER_LEN + message_len; i < total_len; i++) {
        frame_buffer[i] = 0;
    }

    terminal_writestring("NET: Sending frame...\n");

    ne_set_cr(NE_CR_STOP | NE_CR_NO_DMA);
    ne_select_page(0);

    ne_write_reg(NE_TPSR, NE_TX_PAGE);

    ne_write_reg(NE_TBCR0, (uint8_t)(total_len & 0xFF));
    ne_write_reg(NE_TBCR1, (uint8_t)(total_len >> 8));

    ne_rdm_write((uint16_t)NE_TX_PAGE << 8, frame_buffer, total_len);

    ne_set_cr(NE_CR_TXP | NE_CR_START);

    kfree(frame_buffer);
}

int net_ne2000_extension_init(void) {
    terminal_writestring("NET: NE2000 Extension Initializing...\n");

    uint8_t reset_val = inb(io_base + 0x1F);
    outb(io_base + 0x1F, reset_val);
    while ((inb(io_base + NE_ISR) & NE_ISR_RST) == 0) { }
    outb(io_base + NE_ISR, NE_ISR_RST);

    ne_set_cr(NE_CR_STOP | NE_CR_NO_DMA);

    ne_select_page(0);
    ne_write_reg(NE_DCR, 0x48);

    ne_write_reg(NE_TCR, 0x00);

    ne_write_reg(NE_RCR, 0x04); // Changed to Monitor Mode for initial setup

    ne_write_reg(NE_BNRY, NE_START_PAGE);
    ne_select_page(1);
    ne_write_reg(NE_PSTART, NE_START_PAGE);
    ne_write_reg(NE_PSTOP, NE_STOP_PAGE);

    ne_select_page(0);
    ne_write_reg(NE_CR, NE_CR_STOP | NE_CR_NO_DMA);
    ne_write_reg(NE_RCR, 0x20);
    ne_write_reg(NE_TCR, 0x02);

    ne_select_page(1);
    for (int i = 0; i < ETH_MAC_LEN; i++) {
        mac_address[i] = ne_read_reg(NE_PAR0 + i);
    }
    ne_select_page(0);

    for (int i = 0; i < 8; i++) {
        ne_select_page(1);
        ne_write_reg(NE_MAR0 + i, 0x00);
    }
    ne_select_page(0);

    ne_select_page(1);
    ne_write_reg(NE_CURR, NE_START_PAGE + 1);
    current_rx_page = NE_START_PAGE + 1;
    ne_select_page(0);

    ne_write_reg(NE_IMR, NE_ISR_PRX | NE_ISR_PTX | NE_ISR_OVW | NE_ISR_RXE | NE_ISR_TXE);

    ne_write_reg(NE_ISR, 0xFF);

    ne_set_cr(NE_CR_START | NE_CR_NO_DMA);
    ne_write_reg(NE_RCR, 0x0C);
    ne_write_reg(NE_TCR, 0x00);

    terminal_writestring("NET: NE2000 Extension Initialized successfully.\n");
    terminal_writestring("NET: Ready to send and receive frames.\n");

    register_command("net_info", cmd_net_info, "Display NE2000 network info", ne2000_ext_id);
    register_command("net_send", cmd_net_send, "Send raw Ethernet frame (MAC message)", ne2000_ext_id);

    return 0;
}

void net_ne2000_extension_cleanup(void) {
    terminal_writestring("NET: NE2000 Extension Cleaning up...\n");
    ne_set_cr(NE_CR_STOP);
    terminal_writestring("NET: NE2000 Extension Cleanup complete.\n");
}

__attribute__((section(".ext_register_fns")))
void __net_ne2000_auto_register(void) {
    ne2000_ext_id = register_extension("NET_NE2000", "1.0",
                                       net_ne2000_extension_init,
                                       net_ne2000_extension_cleanup);
    if (ne2000_ext_id >= 0) {
        load_extension(ne2000_ext_id);
    } else {
        terminal_writestring("Failed to register NE2000 Network Extension (auto)!\n");
    }
}
