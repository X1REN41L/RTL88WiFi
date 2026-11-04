/* Modified by X1REN41L on 2026-11-04 for RTL88WiFi 1.1.0; see the repository NOTICE.md. */
// SPDX-License-Identifier: GPL-2.0
/*
 * hostap's utils/wpabuf.c, unchanged, with the kext's includes.h taking the
 * place of hostap's: wpabuf.c's own #include "includes.h" finds hostap's
 * header next to it, which wants sockets and stdio, and is then skipped by
 * the shared include guard.
 */
#include "includes.h"
#include "src/utils/wpabuf.c"
