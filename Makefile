# IntentsHelperProbe v1.0.3 - process-internal CPU spike stack sampler
#   v1.0.3: mirror SearchPartyQuiet v1.0.4 EXACT log method: process-owned dir
#           /var/mobile/Library/Intents first, /var/tmp second, NO getenv/TMPDIR/syslog
#   v1.0.2: constructor(100) boot-proof to prove ctor execution && locate writable path
#   v1.0.1: TMPDIR-first logging + syslog diagnostics to locate sandbox-writable path
#   for intents_helper.xpc (roothide, arm64e, diagnostic tool).
# Pure constructor: no substrate/ellekit/Foundation/UIKit link, so a launchd
# XPC service can dlopen it without the silent-failure risk of heavy frameworks.
# Uses mach task_threads/thread_info/thread_get_state, dladdr, pthread - all in libSystem.
export TARGET = iphone:clang:latest:16.0
export ARCHS = arm64e

THEOS_PACKAGE_SCHEME ?= roothide
export THEOS_PACKAGE_SCHEME
export _THEOS_PLATFORM_DPKG_DEB_COMPRESSION = gzip

TWEAK_NAME = IntentsHelperProbe
IntentsHelperProbe_FILES = Tweak.xm
IntentsHelperProbe_CFLAGS = -Os -Wall
IntentsHelperProbe_LDFLAGS = -Wl,-dead_strip_dylibs
ERROR_ON_WARNINGS = 0

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
