import UIKit

// RyBox entry point (replaces @main).
//
// RyBox is a SELF-CONTAINED microkernel container: it always boots the container
// UI (RyBoxAppDelegate). GUI guest apps are launched IN-PROCESS (LiveContainer
// model) from inside the running container — they are NOT launched by relaunching
// this binary. See GuestRuntime / RyBoxGuestBundle for the dlopen + mainBundle
// redirect + entry-point jump mechanism. (No pendingGuest / relaunch switch.)

UIApplicationMain(CommandLine.argc,
                  CommandLine.unsafeArgv,
                  nil,
                  NSStringFromClass(RyBoxAppDelegate.self))
