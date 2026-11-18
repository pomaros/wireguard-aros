/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
#include "wg_freestanding.h"

static char buffer[512];
static size_t used;

static void flush(void) {
    if (used > 0) {
        Write(Output(), buffer, (LONG)used);
        used = 0;
    }
}

static void put(char c) {
    if (used == sizeof(buffer)) {
        flush();
    }
    buffer[used++] = c;
}

static void put_number(unsigned long long v, int negative) {
    char digits[24];
    int n = 0;

    do {
        digits[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    if (negative) {
        put('-');
    }
    while (n > 0) {
        put(digits[--n]);
    }
}

void wg_printf(const char *format, ...) {
    va_list ap;

    va_start(ap, format);
    for (; *format; format++) {
        int longs = 0;

        if (*format != '%') {
            put(*format);
            continue;
        }
        format++;
        while (*format == 'l') {
            longs++;
            format++;
        }
        switch (*format) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            for (s = s ? s : "(null)"; *s; s++) {
                put(*s);
            }
            break;
        }
        case 'c':
            put((char)va_arg(ap, int));
            break;
        case 'd': {
            long long v = longs >= 2 ? va_arg(ap, long long) : longs == 1 ? va_arg(ap, long) : va_arg(ap, int);
            put_number(v < 0 ? 0ULL - (unsigned long long)v : (unsigned long long)v, v < 0);
            break;
        }
        case 'u': {
            unsigned long long v = longs >= 2 ? va_arg(ap, unsigned long long)
                                   : longs == 1 ? va_arg(ap, unsigned long) : va_arg(ap, unsigned int);
            put_number(v, 0);
            break;
        }
        case '%':
            put('%');
            break;
        case 0:
            format--;
            break;
        default:
            put('?');
            break;
        }
    }
    va_end(ap);
    flush();
}
