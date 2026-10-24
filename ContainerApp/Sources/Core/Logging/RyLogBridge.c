// RyBox live-log bridge (C side).
//
// The Swift side owns the log store; the C/ObjC side (guest loader, signer,
// microkernel) pushes lines into it through this tiny bridge so the in-app
// "日志" app and the floating ball show EXACTLY what the container is doing —
// including the guest loader, which is otherwise invisible.

#include "../GuestLoader/RyLogBridge.h"
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

static RyLogSink g_sink = NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void RyLogSetSink(RyLogSink sink) {
    pthread_mutex_lock(&g_lock);
    g_sink = sink;
    pthread_mutex_unlock(&g_lock);
}

void RyLogWrite(const char *level, const char *tag, const char *message) {
    if (!message) return;
    pthread_mutex_lock(&g_lock);
    RyLogSink sink = g_sink;
    pthread_mutex_unlock(&g_lock);
    if (!sink) return;
    sink(level ? level : "info", tag ? tag : "c", message);
}
