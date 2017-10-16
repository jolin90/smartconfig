#include <string.h>
#include <unistd.h>

#include "pcap.h"
#include "iface.h"
#include "cpack.h"
#include "crc32.h"
#include "extract.h"

static u_int get_source_mac = 0;
static u_char from_source_mac[3][6] = { {0}, {0}, {0} };
static const u_char mcast_key0[] = { 0x01, 0x00, 0x5e, 0x00, 0x48, 0x35 };
static const u_char mcast_key1[] = { 0x01, 0x00, 0x5e, 0x01, 0x68, 0x2b };
static const u_char mcast_key2[] = { 0x01, 0x00, 0x5e, 0x02, 0x5c, 0x31 };
static const u_char mcast_key3[] = { 0x01, 0x00, 0x5e, 0x03, 0x00, 0x00 };

static void check_from_source_mac(struct smartconfig *sc)
{
	u_char *source0 = (u_char *) & from_source_mac[0];
	u_char *source1 = (u_char *) & from_source_mac[1];
	u_char *source2 = (u_char *) & from_source_mac[2];

	if (!get_source_mac) {

		if ((source0[0] == 0) && (source0[1] == 0) &&
			(source0[2] == 0) && (source0[3] == 0) && (source0[4] == 0) && (source0[5] == 0))
			return;

		if ((source1[0] == 0) && (source1[1] == 0) &&
			(source1[2] == 0) && (source1[3] == 0) && (source1[4] == 0) && (source1[5] == 0))
			return;

		if ((source2[0] == 0) && (source2[1] == 0) &&
			(source2[2] == 0) && (source2[3] == 0) && (source2[4] == 0) && (source2[5] == 0))
			return;

		if (!memcmp(source0, source1, 6) && !memcmp(source2, source1, 6)) {
			get_source_mac = 1;
			eloop_cancel_timeout(sc->handler, sc, NULL);

			usleep(100);
			printf("get source mac address, and channelfreq: %d\n", sc->channelfreq);
			iface_set_freq(sc->sock_fd, sc->device, sc->channelfreq);
		}
	}
}

static void check_sconf_integrity(struct smartconfig *sc)
{
	int i, count = 0;

	int len = (sc->ssid_len > sc->psk_len ? sc->ssid_len : sc->psk_len);
	if (len > 0) {

		for (i = 0; i < len; i++)
			if (sc->slm[i + 4].flag)
				count++;

		if (count == len) {
			eloop_terminate();
		}
	}
}

static void data_header_print(struct smartconfig *sc, uint16_t fc, const u_char * p, uint16_t channel)
{
#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
#define ADDR4  (p + 24)

	const u_char *mcast = NULL;
	const u_char *source = NULL;

	u_char *source0 = (u_char *) & from_source_mac[0];
	u_char *source1 = (u_char *) & from_source_mac[1];
	u_char *source2 = (u_char *) & from_source_mac[2];

	if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
		mcast = ADDR1;
		source = ADDR3;
	} else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
		mcast = ADDR3;
		source = ADDR2;
	} else
		return;

	//data_frame_dump(mcast, 6);
	//data_frame_dump(source, 6);

	if (get_source_mac) {
		if (!memcmp(source0, source, 6)) {

			if (mcast[3] > MAX_SLINKMAC_LEN)
				return;

			if (!memcmp(mcast_key3, mcast, 4)) {
				if ((mcast[4] <= MAX_SSID_PSK_LEN)
					&& (mcast[5] <= MAX_SSID_PSK_LEN)) {
					sc->ssid_len = mcast[4];
					sc->psk_len = mcast[5];
				}
			} else if (!memcmp(mcast_key3, mcast, 3)) {
				int index = mcast[3];
				memcpy(sc->slm[index].mcast, mcast, 6);
				memcpy(sc->slm[index].source, source, 6);
				sc->slm[index].flag = 1;
			}

			check_sconf_integrity(sc);
		}

	} else {

		if (!memcmp(mcast_key0, mcast, 6)) {
			sc->channelfreq = channel;
			printf("channel0:%d\n", sc->channelfreq);
			memcpy(source0, source, 6);
		}

		if (!memcmp(mcast_key1, mcast, 6)) {
			sc->channelfreq = channel;
			printf("channel1:%d\n", sc->channelfreq);
			memcpy(source1, source, 6);
		}

		if (!memcmp(mcast_key2, mcast, 6)) {
			sc->channelfreq = channel;
			printf("channel2:%d\n", sc->channelfreq);
			memcpy(source2, source, 6);
		}

		check_from_source_mac(sc);
	}

#undef ADDR1
#undef ADDR2
#undef ADDR3
#undef ADDR4
}

static u_int ieee802_11_print(struct smartconfig *sc, const u_char * p,
							  u_int length, u_int orig_caplen, uint16_t channel)
{
	uint16_t fc;

	fc = EXTRACT_LE_16BITS(p);

	uint32_t fcs = *(uint32_t *) (p + length - 4);
	uint32_t crc = getcrc32(p, length - 4);

	if (fcs == crc) {
		if (FC_TYPE(fc) == T_DATA) {
			data_header_print(sc, fc, p, channel);
		}
	}

	return 0;
}

static int print_radiotap_field(struct smartconfig *sc, struct cpack_state *s,
								uint32_t bit, uint8_t * flagsp, uint32_t presentflags, uint16_t * channel)
{
	int rc;

	switch (bit) {

	case IEEE80211_RADIOTAP_TSFT:{
			uint64_t tsft;

			rc = cpack_uint64(s, &tsft);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_FLAGS:{
			uint8_t flagsval;

			rc = cpack_uint8(s, &flagsval);
			if (rc != 0)
				goto trunc;
			*flagsp = flagsval;
			break;
		}

	case IEEE80211_RADIOTAP_RATE:{
			uint8_t rate;

			rc = cpack_uint8(s, &rate);
			if (rc != 0)
				goto trunc;
			break;
		}

	case IEEE80211_RADIOTAP_CHANNEL:{
			uint16_t frequency;
			uint16_t flags;

			rc = cpack_uint16(s, &frequency);
			if (rc != 0)
				goto trunc;
			rc = cpack_uint16(s, &flags);
			if (rc != 0)
				goto trunc;
			*channel = frequency;
			break;
		}

	default:
		return -1;
	}

	return 0;

trunc:
	return rc;
}

static int print_in_radiotap_namespace(struct smartconfig *sc,
									   struct cpack_state *s,
									   uint8_t * flags, uint32_t presentflags, int bit0, uint16_t * channel)
{
#define	BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define	BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define	BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define	BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define	BITNO_2(x) (((x) & 2) ? 1 : 0)

	uint32_t present, next_present;
	int bitno;
	enum ieee80211_radiotap_type bit;
	int rc;

	for (present = presentflags; present; present = next_present) {
		/*
		 * Clear the least significant bit that is set.
		 */
		next_present = present & (present - 1);

		/*
		 * Get the bit number, within this presence word,
		 * of the remaining least significant bit that
		 * is set.
		 */
		bitno = BITNO_32(present ^ next_present);

		/*
		 * Stop if this is one of the "same meaning
		 * in all presence flags" bits.
		 */
		if (bitno >= IEEE80211_RADIOTAP_NAMESPACE)
			break;

		/*
		 * Get the radiotap bit number of that bit.
		 */
		bit = (enum ieee80211_radiotap_type)(bit0 + bitno);

		rc = print_radiotap_field(sc, s, bit, flags, presentflags, channel);
		if (rc != 0)
			return rc;
	}

	return 0;
}

static u_int ieee802_11_radio_print(struct smartconfig *sc, const u_char * p, u_int length, u_int caplen)
{
#define BIT(n)  (1U << n)
#define IS_EXTENDED(__p)    \
	(EXTRACT_LE_32BITS(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

	struct cpack_state cpacker;
	const struct ieee80211_radiotap_header *hdr;
	uint32_t presentflags;
	const uint32_t *presentp;
	u_int len;
	uint16_t channel = 0;
	uint8_t flags;

	if (caplen < sizeof(*hdr)) {
		return caplen;
	}

	hdr = (const struct ieee80211_radiotap_header *)p;
	len = EXTRACT_LE_16BITS(&hdr->it_len);

	if (caplen < len) {
		return caplen;
	}

	cpack_init(&cpacker, (const uint8_t *)hdr, len);	/* align against header start */
	cpack_advance(&cpacker, sizeof(*hdr));	/* includes the 1st bitmap */

	flags = 0;

	presentp = &hdr->it_present;
	presentflags = EXTRACT_LE_32BITS(presentp);
	print_in_radiotap_namespace(sc, &cpacker, &flags, presentflags, 0, &channel);

	return len + ieee802_11_print(sc, p + len, length - len, caplen - len, channel);
}

static u_int ieee802_11_radio_if_print(struct smartconfig *sc, const struct pkthdr *h, const u_char * p)
{
	return ieee802_11_radio_print(sc, p, h->len, h->caplen);
}

void print_packet(struct smartconfig *sc, const struct pkthdr *h, const u_char * sp)
{
#if 0
	static u_int packets_captured = 0;
	printf("packets_captured = %u\n", packets_captured++);
#endif

	ieee802_11_radio_if_print(sc, h, sp);
}
