#pragma once
#include <stdint.h>
#include "mac.h"

#pragma pack(push, 1)
struct radiotap_hdr
{
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t presentFlag;
    uint8_t dataRate;
    uint8_t unknown;
    uint16_t txFlag;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct deauth_hdr
{
    uint8_t     version:2;
    uint8_t     type:2;
    uint8_t     subtype:4;
    uint8_t     flags;
    uint16_t duration;
    Mac bc_receiver_addr;
    Mac bc_transmitter_addr;
    Mac bc_BSSID;
    uint16_t seq;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct wireless_hdr
{
    uint16_t fixed;
};
#pragma pack(pop)