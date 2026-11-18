/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 John Knipper */
/*
 * wireguard.device: a point-to-point SANA-II device whose wire is a
 * WireGuard tunnel.
 *
 * Two rules shape this file. The TCP/IP stack sends its control commands
 * while it holds its own global lock, and the unit task takes that lock in
 * every socket call. So every command except CMD_READ and CMD_WRITE is
 * completed here, in the caller's context, without waiting for the task and
 * without taking the base lock. And closing the last opener never waits for
 * the task: the task owns the unit and frees it when it ends.
 */
#include <aros/libcall.h>
#include <aros/symbolsets.h>
#include <devices/newstyle.h>
#include <exec/errors.h>
#include <exec/memory.h>
#include <utility/tagitem.h>
#include <proto/exec.h>

#include "wg_device.h"
#include LC_LIBDEFS_FILE

struct ExecBase *SysBase;
struct Device *TimerBase;

#define IP_TYPE_PPP 0x0021
#define IP_TYPE_ETHER 0x0800

static const UWORD supported_commands[] = {
    CMD_READ, CMD_WRITE, S2_DEVICEQUERY, S2_GETSTATIONADDRESS, S2_CONFIGINTERFACE, S2_BROADCAST,
    S2_TRACKTYPE, S2_UNTRACKTYPE, S2_GETGLOBALSTATS, S2_ONEVENT, S2_ONLINE, S2_OFFLINE,
    NSCMD_DEVICEQUERY, WGCMD_SETCONFIG, WGCMD_GETSTATUS, WGCMD_CLEAR, 0};

void wg_log(const char *text) {
    /* RawPutChar goes to the serial console. The formatted debug output of
     * exec depends on a debug library that a release system may not have. */
    while (*text) {
        RawPutChar(*text++);
    }
}

static void wipe(void *p, ULONG n) {
    volatile UBYTE *b = p;

    while (n--) {
        *b++ = 0;
    }
}

static int WG_Init(LIBBASETYPEPTR base) {
    SysBase = base->sys_base;
    InitSemaphore(&base->lock);
    base->status.handshake_age = -1;
    if (OpenDevice("timer.device", UNIT_VBLANK, (struct IORequest *)&base->timer_io, 0) != 0) {
        return FALSE;
    }
    TimerBase = base->timer_io.tr_node.io_Device;
    return TRUE;
}

static int WG_Expunge(LIBBASETYPEPTR base) {
    /* A unit task that has not finished still runs this code. */
    if (base->tasks_alive != 0) {
        return FALSE;
    }
    wipe(&base->config, sizeof(base->config));
    CloseDevice((struct IORequest *)&base->timer_io);
    return TRUE;
}

/* The caller's tag list is short and ends with TAG_END. */
static APTR find_tag(struct TagItem *tags, Tag wanted) {
    for (; tags && tags->ti_Tag != TAG_END; tags++) {
        if (tags->ti_Tag == TAG_MORE) {
            tags = (struct TagItem *)tags->ti_Data;
            if (!tags || tags->ti_Tag == TAG_END) {
                break;
            }
        }
        if (tags->ti_Tag == wanted) {
            return (APTR)tags->ti_Data;
        }
    }
    return NULL;
}

static struct WGUnit *unit_create(LIBBASETYPEPTR base) {
    struct WGUnit *unit = AllocMem(sizeof(*unit), MEMF_PUBLIC | MEMF_CLEAR);

    if (!unit) {
        return NULL;
    }
    unit->base = base;
    NEWLIST(&unit->openers);
    NEWLIST(&unit->events);
    unit->sync_port = CreateMsgPort();
    if (unit->sync_port) {
        base->tasks_alive++;
        unit->task = NewCreateTask(TASKTAG_PC, wg_unit_task, TASKTAG_NAME, "wireguard.device", TASKTAG_PRI, 5,
                                   TASKTAG_STACKSIZE, 65536, TASKTAG_ARG1, base, TASKTAG_ARG2, unit, TAG_DONE);
        if (unit->task) {
            /* The task sends start_msg once its ports and signals exist, or with write_port NULL on failure. */
            WaitPort(unit->sync_port);
            GetMsg(unit->sync_port);
            /* The port's signal belongs to this task, the opener, so it is freed here. */
            DeleteMsgPort(unit->sync_port);
            unit->sync_port = NULL;
            if (unit->write_port) {
                return unit;
            }
            /* The task failed to start and has ended; it left the unit to us. */
            FreeMem(unit, sizeof(*unit));
            return NULL;
        } else {
            base->tasks_alive--;
        }
        DeleteMsgPort(unit->sync_port);
    }
    FreeMem(unit, sizeof(*unit));
    return NULL;
}

static int WG_Open(LIBBASETYPEPTR base, struct IOSana2Req *req, ULONG unitnum, ULONG flags) {
    struct TagItem *tags = req->ios2_BufferManagement;
    struct WGOpener *opener;
    struct WGUnit *unit;

    req->ios2_Req.io_Unit = NULL;
    req->ios2_BufferManagement = NULL;
    req->ios2_Req.io_Error = IOERR_OPENFAIL;

    if (unitnum != 0) {
        return FALSE;
    }
    opener = AllocMem(sizeof(*opener), MEMF_PUBLIC | MEMF_CLEAR);
    if (!opener) {
        return FALSE;
    }
    NEWLIST(&opener->read_pending.mp_MsgList);
    opener->read_pending.mp_Flags = PA_IGNORE;
    opener->rx = find_tag(tags, S2_CopyToBuff);
    opener->tx = find_tag(tags, S2_CopyFromBuff);

    /* Open and Close run one at a time: exec holds the device list lock around them. */
    unit = base->unit;
    if (!unit) {
        unit = unit_create(base);
        if (!unit) {
            FreeMem(opener, sizeof(*opener));
            return FALSE;
        }
        base->unit = unit;
        wg_log("[wireguard] unit task started\n");
    }
    Disable();
    AddTail((struct List *)&unit->openers, (struct Node *)opener);
    Enable();
    unit->refcount++;

    req->ios2_Req.io_Unit = (struct Unit *)unit;
    req->ios2_BufferManagement = opener;
    req->ios2_Req.io_Error = 0;
    return TRUE;
}

static void reply_parked(struct List *list, BYTE error, ULONG wire_error) {
    struct IOSana2Req *req;

    for (;;) {
        Disable();
        req = (struct IOSana2Req *)RemHead(list);
        Enable();
        if (!req) {
            break;
        }
        req->ios2_Req.io_Error = error;
        req->ios2_WireError = wire_error;
        ReplyMsg((struct Message *)req);
    }
}

static int WG_Close(LIBBASETYPEPTR base, struct IOSana2Req *req) {
    struct WGUnit *unit = (struct WGUnit *)req->ios2_Req.io_Unit;
    struct WGOpener *opener = req->ios2_BufferManagement;

    if (!unit || !opener) {
        return TRUE;
    }
    Disable();
    Remove((struct Node *)opener);
    Enable();
    reply_parked(&opener->read_pending.mp_MsgList, IOERR_ABORTED, S2WERR_GENERIC_ERROR);
    FreeMem(opener, sizeof(*opener));
    req->ios2_Req.io_Unit = NULL;
    req->ios2_BufferManagement = NULL;

    if (--unit->refcount == 0) {
        reply_parked((struct List *)&unit->events, IOERR_ABORTED, S2WERR_GENERIC_ERROR);
        base->unit = NULL;
        /* The task replies queued writes, frees the unit and ends. Nobody waits for it. */
        Signal(unit->task, 1UL << unit->stop_signal);
        wg_log("[wireguard] last opener closed, unit task told to stop\n");
    }
    return TRUE;
}

ADD2INITLIB(WG_Init, 0)
ADD2EXPUNGELIB(WG_Expunge, 0)
ADD2OPENDEV(WG_Open, 0)
ADD2CLOSEDEV(WG_Close, 0)

/* Completes the parked S2_ONEVENT requests that asked for one of these events. */
static void post_events(struct WGUnit *unit, ULONG events) {
    struct IOSana2Req *req, *next;
    struct MinList done;

    NEWLIST(&done);
    Disable();
    for (req = (struct IOSana2Req *)unit->events.mlh_Head; (next = (struct IOSana2Req *)req->ios2_Req.io_Message.mn_Node.ln_Succ);
         req = next) {
        if (req->ios2_WireError & events) {
            Remove((struct Node *)req);
            AddTail((struct List *)&done, (struct Node *)req);
        }
    }
    Enable();
    while ((req = (struct IOSana2Req *)RemHead((struct List *)&done))) {
        req->ios2_WireError &= events;
        req->ios2_Req.io_Error = 0;
        ReplyMsg((struct Message *)req);
    }
}

static void fill_query(struct Sana2DeviceQuery *q) {
    ULONG size = q->SizeAvailable;
    struct Sana2DeviceQuery full;

    wipe(&full, sizeof(full));
    full.SizeAvailable = size;
    full.SizeSupplied = size < sizeof(full) ? size : sizeof(full);
    full.DevQueryFormat = 0;
    full.DeviceLevel = 0;
    full.AddrFieldSize = 0;           /* a point-to-point link has no station address */
    full.MTU = WG_DEVICE_MTU;
    full.BPS = 100000000;
    full.HardwareType = S2WireType_PPP;
    CopyMem(&full, q, full.SizeSupplied);
}

static BOOL private_command(LIBBASETYPEPTR base, struct WGUnit *unit, struct IOSana2Req *req) {
    switch (req->ios2_Req.io_Command) {
    case WGCMD_SETCONFIG:
        if (!req->ios2_StatData || req->ios2_DataLength != sizeof(struct WGDeviceConfig)) {
            req->ios2_Req.io_Error = S2ERR_BAD_ARGUMENT;
            return TRUE;
        }
        ObtainSemaphore(&base->lock);
        CopyMem(req->ios2_StatData, &base->config, sizeof(base->config));
        base->config_valid = TRUE;
        base->config_serial++;
        ReleaseSemaphore(&base->lock);
        Signal(unit->task, 1UL << unit->config_signal);
        return TRUE;
    case WGCMD_CLEAR:
        ObtainSemaphore(&base->lock);
        wipe(&base->config, sizeof(base->config));
        base->config_valid = FALSE;
        base->config_serial++;
        ReleaseSemaphore(&base->lock);
        Signal(unit->task, 1UL << unit->config_signal);
        return TRUE;
    case WGCMD_GETSTATUS:
        if (!req->ios2_StatData || req->ios2_DataLength != sizeof(struct WGDeviceStatus)) {
            req->ios2_Req.io_Error = S2ERR_BAD_ARGUMENT;
            return TRUE;
        }
        ObtainSemaphore(&base->lock);
        base->status.online = (unit->flags & WGUF_ONLINE) != 0;
        CopyMem(&base->status, req->ios2_StatData, sizeof(base->status));
        ReleaseSemaphore(&base->lock);
        return TRUE;
    }
    return FALSE;
}

AROS_LH1(void, WG_BeginIO, AROS_LHA(struct IOSana2Req *, req, A1), LIBBASETYPEPTR, base, 5, WireGuard) {
    AROS_LIBFUNC_INIT

    struct WGUnit *unit = (struct WGUnit *)req->ios2_Req.io_Unit;
    struct WGOpener *opener = req->ios2_BufferManagement;
    BOOL done = TRUE;

    req->ios2_Req.io_Error = 0;
    req->ios2_WireError = req->ios2_Req.io_Command == S2_ONEVENT ? req->ios2_WireError : 0;
    req->ios2_Req.io_Message.mn_Node.ln_Type = NT_MESSAGE;

    switch (req->ios2_Req.io_Command) {
    case CMD_READ:
        if (!(unit->flags & WGUF_ONLINE)) {
            req->ios2_Req.io_Error = S2ERR_OUTOFSERVICE;
            req->ios2_WireError = S2WERR_UNIT_OFFLINE;
            break;
        }
        if (!opener->rx) {
            req->ios2_Req.io_Error = S2ERR_NOT_SUPPORTED;
            break;
        }
        req->ios2_Req.io_Flags &= ~IOF_QUICK;
        Disable();
        AddTail(&opener->read_pending.mp_MsgList, (struct Node *)req);
        Enable();
        done = FALSE;
        break;

    case CMD_WRITE:
    case S2_BROADCAST:
        if (!(unit->flags & WGUF_ONLINE)) {
            req->ios2_Req.io_Error = S2ERR_OUTOFSERVICE;
            req->ios2_WireError = S2WERR_UNIT_OFFLINE;
            break;
        }
        if (!opener->tx || req->ios2_DataLength > WG_DEVICE_MTU) {
            req->ios2_Req.io_Error = S2ERR_MTU_EXCEEDED;
            break;
        }
        req->ios2_Req.io_Flags &= ~IOF_QUICK;
        PutMsg(unit->write_port, (struct Message *)req);
        done = FALSE;
        break;

    case S2_DEVICEQUERY:
        if (req->ios2_StatData) {
            fill_query(req->ios2_StatData);
        } else {
            req->ios2_Req.io_Error = S2ERR_BAD_ARGUMENT;
        }
        break;

    case S2_GETSTATIONADDRESS:
        break; /* zero address bytes */

    case S2_CONFIGINTERFACE:
        if (unit->flags & WGUF_CONFIGURED) {
            req->ios2_Req.io_Error = S2ERR_BAD_STATE;
            req->ios2_WireError = S2WERR_IS_CONFIGURED;
        } else {
            unit->flags |= WGUF_CONFIGURED | WGUF_ONLINE;
        }
        break;

    case S2_ONLINE:
        if (unit->flags & WGUF_ONLINE) {
            req->ios2_Req.io_Error = S2ERR_BAD_STATE;
            req->ios2_WireError = S2WERR_UNIT_ONLINE;
        } else {
            unit->flags |= WGUF_ONLINE;
            post_events(unit, S2EVENT_ONLINE);
        }
        break;

    case S2_OFFLINE:
        if (!(unit->flags & WGUF_ONLINE)) {
            req->ios2_Req.io_Error = S2ERR_BAD_STATE;
            req->ios2_WireError = S2WERR_UNIT_OFFLINE;
        } else {
            struct WGOpener *o;
            unit->flags &= ~WGUF_ONLINE;
            for (o = (struct WGOpener *)unit->openers.mlh_Head; o->node.mln_Succ; o = (struct WGOpener *)o->node.mln_Succ) {
                reply_parked(&o->read_pending.mp_MsgList, S2ERR_OUTOFSERVICE, S2WERR_UNIT_OFFLINE);
            }
            post_events(unit, S2EVENT_OFFLINE);
        }
        break;

    case S2_ONEVENT: {
        ULONG now = (unit->flags & WGUF_ONLINE) ? S2EVENT_ONLINE : S2EVENT_OFFLINE;
        if (req->ios2_WireError & now) {
            req->ios2_WireError &= now;
            break;
        }
        req->ios2_Req.io_Flags &= ~IOF_QUICK;
        Disable();
        AddTail((struct List *)&unit->events, (struct Node *)req);
        Enable();
        done = FALSE;
        break;
    }

    case S2_TRACKTYPE:
    case S2_UNTRACKTYPE:
        break;

    case S2_GETGLOBALSTATS:
        if (req->ios2_StatData) {
            CopyMem(&unit->stats, req->ios2_StatData, sizeof(unit->stats));
        } else {
            req->ios2_Req.io_Error = S2ERR_BAD_ARGUMENT;
        }
        break;

    case NSCMD_DEVICEQUERY: {
        struct IOStdReq *std = (struct IOStdReq *)req;
        struct NSDeviceQueryResult *result = std->io_Data;
        if (!result || std->io_Length < sizeof(*result)) {
            req->ios2_Req.io_Error = IOERR_BADLENGTH;
            break;
        }
        result->DevQueryFormat = 0;
        result->SizeAvailable = sizeof(*result);
        result->DeviceType = NSDEVTYPE_SANA2;
        result->DeviceSubType = 0;
        result->SupportedCommands = (UWORD *)supported_commands;
        std->io_Actual = sizeof(*result);
        break;
    }

    default:
        if (!private_command(base, unit, req)) {
            req->ios2_Req.io_Error = IOERR_NOCMD;
            req->ios2_WireError = S2WERR_GENERIC_ERROR;
        }
        break;
    }

    if (done && !(req->ios2_Req.io_Flags & IOF_QUICK)) {
        ReplyMsg((struct Message *)req);
    }

    AROS_LIBFUNC_EXIT
}

static BOOL remove_from(struct List *list, struct IOSana2Req *req) {
    struct Node *node;
    BOOL found = FALSE;

    Disable();
    for (node = list->lh_Head; node->ln_Succ; node = node->ln_Succ) {
        if (node == (struct Node *)req) {
            Remove(node);
            found = TRUE;
            break;
        }
    }
    Enable();
    return found;
}

AROS_LH1(LONG, WG_AbortIO, AROS_LHA(struct IOSana2Req *, req, A1), LIBBASETYPEPTR, base, 6, WireGuard) {
    AROS_LIBFUNC_INIT

    struct WGUnit *unit = (struct WGUnit *)req->ios2_Req.io_Unit;
    struct WGOpener *opener = req->ios2_BufferManagement;

    /* A request is parked on one of three lists; whoever unlinks it replies to it. */
    if (!unit || !opener ||
        !(remove_from(&opener->read_pending.mp_MsgList, req) || remove_from((struct List *)&unit->events, req) ||
          remove_from(&unit->write_port->mp_MsgList, req))) {
        return -1;
    }
    req->ios2_Req.io_Error = IOERR_ABORTED;
    req->ios2_WireError = S2WERR_GENERIC_ERROR;
    ReplyMsg((struct Message *)req);
    return 0;

    AROS_LIBFUNC_EXIT
}
