LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := src/client.c src/vpn_config.c lib/crypto.c

LOCAL_MODULE := vpnclient

LOCAL_MODULE_TAGS := optional

LOCAL_SHARED_LIBRARIES := libc libm libdl liblog

LOCAL_STATIC_LIBRARIES := libcrypto_static libssl_static

LOCAL_C_INCLUDES := $(LOCAL_PATH)/includes

LOCAL_CFLAGS := \
    -std=gnu11 -g -Wall -Wextra -O2 -rdynamic \

LOCAL_LDFLAGS := -Wl,-export-dynamic -Wl,--no-gc-sections

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := src/server.c src/vpn_config.c lib/crypto.c

LOCAL_MODULE := vpnserver

LOCAL_MODULE_TAGS := optional

LOCAL_SHARED_LIBRARIES := libc libm libdl liblog

LOCAL_STATIC_LIBRARIES := libcrypto_static libssl_static

LOCAL_C_INCLUDES := $(LOCAL_PATH)/includes

LOCAL_CFLAGS := \
    -std=gnu11 -g -Wall -Wextra -O2 -rdynamic \

LOCAL_LDFLAGS := -Wl,-export-dynamic -Wl,--no-gc-sections

include $(BUILD_EXECUTABLE)