/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
/*
 * The commands are built without the C library and without the SDK's
 * startup code: they call exec, dos and the network libraries only, so one
 * binary runs on every AROS AArch64 system whatever SDK built it. This
 * header gives them an entry point, a small printf and the string
 * functions of wg_ministring.c.
 */
#ifndef WG_FREESTANDING_H
#define WG_FREESTANDING_H

#include <stdarg.h>
#include <stddef.h>

#include <aros/startup.h>
#include <dos/dos.h>
#include <exec/execbase.h>
#include <proto/dos.h>
#include <proto/exec.h>

extern struct ExecBase *SysBase;
extern struct DosLibrary *DOSBase;

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
char *strcpy(char *dst, const char *src);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
char *strstr(const char *haystack, const char *needle);
int strncmp(const char *a, const char *b, size_t n);
int strcmp(const char *a, const char *b);

/* %s %c %d %u %ld %lu %lld %llu and %%. */
void wg_printf(const char *format, ...);

/*
 * WG_MAIN(name) defines the program's entry point, which must be the first
 * code of the binary, and calls int name(void) with SysBase and DOSBase set.
 */
#define WG_MAIN(name)                                                         \
    static int name(void);                                                    \
    struct ExecBase *SysBase;                                                 \
    struct DosLibrary *DOSBase;                                               \
    __startup AROS_PROCH(wg_entry, argstr, argsize, sysBase) {                \
        AROS_PROCFUNC_INIT                                                    \
        int rc = RETURN_FAIL;                                                 \
        SysBase = sysBase;                                                    \
        DOSBase = (struct DosLibrary *)OpenLibrary("dos.library", 0);         \
        if (DOSBase) {                                                        \
            rc = name();                                                      \
            CloseLibrary((struct Library *)DOSBase);                          \
        }                                                                     \
        return rc;                                                            \
        AROS_PROCFUNC_EXIT                                                    \
    }

#endif
