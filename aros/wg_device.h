/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
#ifndef WG_DEVICE_H
#define WG_DEVICE_H

#include <exec/devices.h>
#include <exec/execbase.h>
#include <exec/lists.h>
#include <exec/ports.h>
#include <exec/semaphores.h>
#include <exec/tasks.h>
#include <exec/types.h>
#include <devices/sana2.h>
#include <devices/timer.h>

#include "wireguard_device.h"

struct WGUnit;

struct WGBase {
    struct Device device;
    struct ExecBase *sys_base;

    struct timerequest timer_io;      /* keeps timer.device open; gives TimerBase */

    /* The lock covers config, config_valid, config_serial and status. It is
     * never taken by a command the TCP/IP stack sends. */
    struct SignalSemaphore lock;
    struct WGDeviceConfig config;
    BOOL config_valid;
    ULONG config_serial;
    struct WGDeviceStatus status;

    struct WGUnit *unit;              /* the one unit, while it is open */
    ULONG tasks_alive;                /* unit tasks that have not finished */
};

struct WGOpener {
    struct MinNode node;
    struct MsgPort read_pending;      /* parked CMD_READ requests, never signalled */
    APTR rx;                          /* S2_CopyToBuff */
    APTR tx;                          /* S2_CopyFromBuff */
};

#define WGUF_CONFIGURED (1 << 0)
#define WGUF_ONLINE     (1 << 1)

struct WGUnit {
    struct WGBase *base;
    ULONG refcount;
    ULONG flags;
    struct MinList openers;
    struct MinList events;            /* parked S2_ONEVENT requests */
    struct MsgPort *write_port;       /* CMD_WRITE requests for the task */
    struct MsgPort *sync_port;        /* start handshake with the task */
    struct Message start_msg;
    struct Task *task;
    LONG stop_signal;
    LONG config_signal;
    struct Sana2DeviceStats stats;
};

void wg_unit_task(struct WGBase *base, struct WGUnit *unit);

#endif
