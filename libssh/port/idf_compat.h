#pragma once

#include "esp_idf_version.h"
#include "termios.h"
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
#include "net/if.h"
#else

// Provide declaration for socket-utils (in older IDFs)
const char *gai_strerror(int errcode);
int socketpair(int domain, int type, int protocol, int sv[2]);
#endif

// IDF compatible macros

// socket utils
#define PF_UNIX AF_UNIX

// termios
#ifndef IMAXBEL
#define IMAXBEL 0
#endif

#ifndef ECHOCTL
#define ECHOCTL 0
#endif

#ifndef ECHOKE
#define ECHOKE 0
#endif

#ifndef PENDIN
#define PENDIN 0
#endif

#ifndef VEOL2
#define VEOL2 0
#endif

#ifndef VREPRINT
#define VREPRINT 0
#endif

#ifndef VWERASE
#define VWERASE 0
#endif

#ifndef VLNEXT
#define VLNEXT 0
#endif

#ifndef VDISCARD
#define VDISCARD 0
#endif
