/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
/*
 * The five C library functions the device and the WireGuard core use, so
 * that the device opens no C library.
 */
#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;

    while (n--) {
        *d++ = *s++;
    }
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;

    if (d < s) {
        while (n--) {
            *d++ = *s++;
        }
    } else {
        while (n--) {
            d[n] = s[n];
        }
    }
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    /* volatile keeps the compiler from turning the loop into a call to memset. */
    volatile unsigned char *d = dst;

    while (n--) {
        *d++ = (unsigned char)c;
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;

    for (; n--; x++, y++) {
        if (*x != *y) {
            return *x - *y;
        }
    }
    return 0;
}

size_t strlen(const char *s) {
    size_t n = 0;

    while (s[n]) {
        n++;
    }
    return n;
}

char *strcpy(char *dst, const char *src) {
    char *d = dst;

    while ((*d++ = *src++)) {
    }
    return dst;
}

char *strchr(const char *s, int c) {
    for (;; s++) {
        if (*s == (char)c) {
            return (char *)s;
        }
        if (!*s) {
            return NULL;
        }
    }
}

char *strrchr(const char *s, int c) {
    const char *last = NULL;

    for (;; s++) {
        if (*s == (char)c) {
            last = s;
        }
        if (!*s) {
            return (char *)last;
        }
    }
}

int strncmp(const char *a, const char *b, size_t n) {
    for (; n--; a++, b++) {
        if (*a != *b || !*a) {
            return (unsigned char)*a - (unsigned char)*b;
        }
    }
    return 0;
}

int strcmp(const char *a, const char *b) {
    return strncmp(a, b, (size_t)-1);
}

char *strstr(const char *haystack, const char *needle) {
    size_t n = strlen(needle);

    for (; *haystack; haystack++) {
        if (strncmp(haystack, needle, n) == 0) {
            return (char *)haystack;
        }
    }
    return n == 0 ? (char *)haystack : NULL;
}
