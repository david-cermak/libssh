set(LIBSSH_VERSION "0.11.0")
set(LIBSSH_DIR "libssh-${LIBSSH_VERSION}")

set(libssh_SRCS
  agent.c
  auth.c
  base64.c
  bignum.c
  buffer.c
  callbacks.c
  channels.c
  client.c
  config.c
  connect.c
  connector.c
  crypto_common.c
  curve25519.c
  dh.c
  ecdh.c
  error.c
  getpass.c
  init.c
  kdf.c
  kex.c
  known_hosts.c
  knownhosts.c
  legacy.c
  log.c
  match.c
  messages.c
  misc.c
  options.c
  packet.c
  packet_cb.c
  packet_crypt.c
  pcap.c
  pki.c
  pki_container_openssh.c
  poll.c
  session.c
  scp.c
  socket.c
  string.c
  threads.c
  ttyopts.c
  wrapper.c
  external/bcrypt_pbkdf.c
  external/blowfish.c
  config_parser.c
  token.c
  pki_ed25519_common.c
)


set(libssh_SRCS
${libssh_SRCS}
threads/mbedtls.c
libmbedcrypto.c
mbedcrypto_missing.c
pki_mbedcrypto.c
ecdh_mbedcrypto.c
getrandom_mbedcrypto.c
md_mbedcrypto.c
dh_key.c
pki_ed25519.c
external/ed25519.c
external/fe25519.c
external/ge25519.c
external/sc25519.c
)

set(libssh_SRCS
${libssh_SRCS}
external/chacha.c
external/poly1305.c
chachapoly.c
)


set(libssh_SRCS
${libssh_SRCS}
server.c
bind.c
bind_config.c
)

set(libssh_SRCS
${libssh_SRCS}
threads/noop.c
threads/pthread.c
)

set(libssh_SRCS
${libssh_SRCS}
external/curve25519_ref.c
)


list(TRANSFORM libssh_SRCS PREPEND "${LIBSSH_DIR}/src/")

idf_component_register(SRCS ${libssh_SRCS}
                    INCLUDE_DIRS ${LIBSSH_DIR}/include .
                    PRIV_REQUIRES esp_netif mbedtls)

target_compile_definitions(${COMPONENT_LIB} PRIVATE LIBSSH_STATIC)
target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-format")
target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-int-conversion")
target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-char-subscripts")
