/*
 * mbedTLS User Configuration File
 *
 * This file contains mbedTLS configuration options that are not available
 * via Zephyr's Kconfig system but are required for libssh compatibility.
 */

#ifndef MBEDTLS_USER_CONFIG_H
#define MBEDTLS_USER_CONFIG_H

/* Enable cipher padding support (required for CBC mode padding operations) */
#define MBEDTLS_CIPHER_MODE_WITH_PADDING

/* Enable ASN1 write support (required for ECDSA certificate operations) */
#define MBEDTLS_ASN1_WRITE_C

/* Enable error string functions (required for error reporting) */
#define MBEDTLS_ERROR_C

#define MBEDTLS_THREADING_PTHREAD
#define MBEDTLS_THREADING_C

#endif /* MBEDTLS_USER_CONFIG_H */
