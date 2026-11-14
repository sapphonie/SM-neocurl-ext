# Static, position independent release libraries for linking into curl.ext.so.
set(VCPKG_TARGET_ARCHITECTURE x86)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
set(VCPKG_BUILD_TYPE release)

# Debian's CA bundle and directory; OpenSSL's default store (/etc/ssl) is the fallback.
if(PORT STREQUAL "curl")
    set(VCPKG_CMAKE_CONFIGURE_OPTIONS
        -DCURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
        -DCURL_CA_PATH=/etc/ssl/certs
    )
endif()
