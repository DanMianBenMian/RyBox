#ifndef RyLogBridge_h
#define RyLogBridge_h
#ifdef __cplusplus
extern "C" {
#endif

/// Sink signature used by the C/ObjC side to push lines into RyBox's live log.
/// The strings are UTF-8 and only valid for the duration of the call.
typedef void (*RyLogSink)(const char *level, const char *tag, const char *message);

/// Install the sink that receives every `RyLogWrite` call. Pass NULL to detach.
void RyLogSetSink(RyLogSink sink);

/// Emit one line into RyBox's live log. Safe to call from any thread.
/// `level` is one of "debug" / "info" / "warn" / "error" (anything else → info),
/// `tag` is a short subsystem name ("guest", "sign", "ui", …).
void RyLogWrite(const char *level, const char *tag, const char *message);

#ifdef __cplusplus
}
#endif
#endif /* RyLogBridge_h */
