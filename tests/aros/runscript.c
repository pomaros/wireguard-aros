/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
/*
 * Test helper: executes the shell script VMWORK0:wg-test.script. A test
 * image installs it under the name of a program its startup already runs,
 * because the startup script of the PomAROS QEMU image lives in the boot
 * bundle and cannot be edited on the disk.
 */
#include "wg_freestanding.h"

WG_MAIN(run_script)

static int run_script(void) {
    return (int)SystemTagList((STRPTR) "SYS:C/Execute VMWORK0:wg-test.script", NULL);
}
