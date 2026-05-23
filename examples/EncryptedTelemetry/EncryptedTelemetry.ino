/**
 * @file EncryptedTelemetry.ino
 * @brief Kestrel Library Example: Full ChaCha20-Poly1305 encrypted telemetry.
 *
 * Demonstrates AEAD-encrypted packet TX/RX on a single ESP32 in loopback
 * mode (Serial1 TX → Serial1 RX via hardware jumper, or using two ESP32s).
 *
 * REQUIRES: ESP32, RP2040, SAMD, or ARM-based Arduino (NOT AVR Uno/Mega)
 *           KS_ARDUINO_NO_CRYPTO must be 0 (auto-set for ESP32)
 *
 * Wiring (loopback on ESP32):
 *   GPIO17 (TX1) → GPIO16 (RX1) with a wire
 *
 * What it shows:
 *   - ks_session_init() for key + nonce state setup
 *   - kestrel_pack_with_nonce() producing encrypted+authenticated packets
 *   - ks_parse_char() + session key to decrypt and verify incoming packets
 *   - Full round-trip: attitude telemetry encrypted → sent → received → decoded
 */

#include <Kestrel.h>

/* -----------------------------------------------------------------------
 * Build guard: this example cannot run on AVR
 * --------------------------------------------------------------------- */
#if defined(KS_ARDUINO_NO_CRYPTO) && KS_ARDUINO_NO_CRYPTO
  #error "EncryptedTelemetry requires crypto support. Use an ESP32, RP2040, or ARM board."
#endif

/* -----------------------------------------------------------------------
 * Shared session key (32 bytes)
 * In production: load from secure storage, derive via ECDH handshake.
 * For this demo both sides use the same hardcoded key.
 * --------------------------------------------------------------------- */
static const uint8_t DEMO_KEY[32] = {
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
  0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
  0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};

static ks_session_t g_tx_session;   /* TX side session (manages nonce)  */
static ks_session_t g_rx_session;   /* RX side session (same key)       */
static ks_parser_t  g_parser;

static uint16_t g_seq = 0;

void setup() {
  Serial.begin(115200);
  while (!Serial) { ; }
  Serial.println(F("=== Kestrel EncryptedTelemetry (ESP32) ==="));

  /* Hardware Serial1: TX=17, RX=16 (loopback jumper needed) */
  Serial1.begin(115200, SERIAL_8N1, 16, 17);

  /* Initialise TX session (seeds nonce from ESP32 hardware RNG) */
  if (ks_session_init(&g_tx_session, DEMO_KEY) != 0) {
    Serial.println(F("ERROR: TX session init failed (CSPRNG?)"));
    while (1) { ; }
  }

  /* Initialise RX session with the same key */
  if (ks_session_init(&g_rx_session, DEMO_KEY) != 0) {
    Serial.println(F("ERROR: RX session init failed"));
    while (1) { ; }
  }

  ks_parser_init(&g_parser);

  Serial.println(F("Session keys initialised. Sending encrypted attitude @ 2 Hz ..."));
}

void loop() {
  /* -----------------------------------------------------------------------
   * TX: build and send an encrypted attitude packet
   * --------------------------------------------------------------------- */
  {
    ks_attitude_t att;
    att.roll       =  0.523f;    /* ~30°  */
    att.pitch      = -0.174f;    /* ~-10° */
    att.yaw        =  1.571f;    /* ~90°  */
    att.rollspeed  =  0.01f;
    att.pitchspeed =  0.005f;
    att.yawspeed   =  0.002f;

    uint8_t payload[16];
    int payload_len = ks_serialize_attitude(&att, payload);

    ks_header_t header;
    memset(&header, 0, sizeof(header));
    header.payload_len = (uint16_t)payload_len;
    header.stream_type = KS_STREAM_TELEM_FAST;
    header.priority    = KS_PRIO_NORMAL;
    header.sequence    = g_seq++ & 0x0FFF;
    header.sys_id      = 1;
    header.comp_id     = 1;
    header.msg_id      = KS_MSG_ATTITUDE;
    header.encrypted   = true;   /* Request encryption */

    uint8_t buf[128];
    /* Pass &g_tx_session — this encrypts the payload with AEAD + appends MAC */
    int packet_len = kestrel_pack_with_nonce(buf, &header, payload, &g_tx_session);

    if (packet_len > 0) {
      Serial1.write(buf, packet_len);
      Serial.print(F("[TX] Encrypted attitude packet, "));
      Serial.print(packet_len);
      Serial.println(F(" bytes"));
    }
  }

  /* -----------------------------------------------------------------------
   * RX: drain Serial1 and parse any complete packets
   * --------------------------------------------------------------------- */
  while (Serial1.available()) {
    uint8_t c = (uint8_t)Serial1.read();

    /* Pass g_rx_session.key to decrypt + verify MAC */
    int result = ks_parse_char(&g_parser, c, g_rx_session.key);

    if (result == KS_OK) {
      if (g_parser.header.msg_id == KS_MSG_ATTITUDE) {
        ks_attitude_t dec;
        ks_deserialize_attitude(&dec, g_parser.payload);
        Serial.print(F("[RX] Decrypted attitude: roll="));
        Serial.print(dec.roll, 3);
        Serial.print(F(" pitch="));
        Serial.print(dec.pitch, 3);
        Serial.print(F(" yaw="));
        Serial.println(dec.yaw, 3);
      }
    } else if (result == KS_ERR_MAC_VERIFICATION) {
      Serial.println(F("[RX] ERROR: MAC verification failed — tampered or wrong key!"));
    } else if (result == KS_ERR_CRC) {
      Serial.println(F("[RX] ERROR: CRC mismatch"));
    }
  }

  delay(500);  /* 2 Hz */
}
