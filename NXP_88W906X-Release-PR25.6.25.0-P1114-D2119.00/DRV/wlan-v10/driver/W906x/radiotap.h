/*
 * Copyright (c) 2017           Intel Deutschland GmbH
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef __RADIOTAP_H
#define __RADIOTAP_H

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#include <machine/endian.h>
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#endif	/* 
    
/**
 * struct ieee82011_radiotap_header - base radiotap header
 */ 
    struct ieee80211_radiotap_header {
	
	/**
	 * @it_version: radiotap version, always 0
	 */ 
	uint8_t it_version;
	
	/**
	 * @it_pad: padding (or alignment)
	 */ 
	uint8_t it_pad;
	
	/**
	 * @it_len: overall radiotap header length
	 */ 
	uint16_t it_len;
	
	/**
	 * @it_present: (first) present word
	 */ 
	uint32_t it_present;


/* version is always 0 */ 
#define PKTHDR_RADIOTAP_VERSION	0
    
/* see the radiotap website for the descriptions */ 
    enum ieee80211_radiotap_presence { 
	    2, 
	    5, 
	    8, 
	    11, 
	    14, 
	    /* 18 is XChannel, but it's not defined yet */ 
	    IEEE80211_RADIOTAP_MCS = 19, 
	    // Added ++
	    IEEE80211_RADIOTAP_HE_INFO = 23, 
	    // Added --
	    
	    /* valid in every it_present bitmap, even vendor namespaces */ 
	IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29, 
};

/* for IEEE80211_RADIOTAP_FLAGS */ 
enum ieee80211_radiotap_flags { 
	    0x04, 
	    0x20, 
};

/* for IEEE80211_RADIOTAP_CHANNEL */ 
enum ieee80211_radiotap_channel_flags { 
	    0x0080, 
};

/* for IEEE80211_RADIOTAP_RX_FLAGS */ 
enum ieee80211_radiotap_rx_flags { 
};

/* for IEEE80211_RADIOTAP_TX_FLAGS */ 
enum ieee80211_radiotap_tx_flags { 
	    0x0004, 
};

/* for IEEE80211_RADIOTAP_MCS "have" flags */ 
enum ieee80211_radiotap_mcs_have { 
	    0x02, 
	    0x10, 
};

	    1, 
	    0x04, 
	    0x60, 
	    3, 
};

/* for IEEE80211_RADIOTAP_AMPDU_STATUS */ 
enum ieee80211_radiotap_ampdu_flags { 
	    0x0002, 
	    0x0008, 
};

/* for IEEE80211_RADIOTAP_VHT */ 
enum ieee80211_radiotap_vht_known { 
	    0x0002, 
	    0x0008, 
	    0x0020, 
	    0x0080, 
};

	    0x02, 
	    0x08, 
};

	    0x02, 
};

/* for IEEE80211_RADIOTAP_TIMESTAMP */ 
enum ieee80211_radiotap_timestamp_unit_spos { 
	    0x0000, 
	    0x0003, 
	    0x0000, 
	    0x0020, 
};

	    0x01, 
};

};

};

	


#endif	/* __RADIOTAP_H */
    