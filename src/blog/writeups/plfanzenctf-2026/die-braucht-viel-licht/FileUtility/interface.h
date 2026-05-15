#pragma once
// Userspace-facing interface to the driver

// debug handlers give arbitrary alloc and R/W for debugging your exploit
// these are off on remote ;)
#define DEBUG_HANDLERS 0

// provide definition of CTL_CODE to userspace so it doesn't need to include ntddk.h
#ifndef CTL_CODE
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#endif

// Device type           -- in the "User Defined" range."
//
#define FILEUTIL_TYPE 40000
//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define FILEUTIL_FUNCTION_CODE_BASE 0x800


// File Utitlity IOCTL calling convention (excluding debug handlers)
// All of the IOCTLs are called in the same way:
// - File handle is passed _directly_ as the `InputBuffer` parameter. Don't pass a userspace pointer to the handle, but instead cast the handle to (PVOID) and pass it directly.
//   Accordingly, `InputBufferSize` is set to 0
// - The OutputBuffer will be the corresponding FILEUTIL_*_INFORMATION struct depending on the method. The pointer must be a userspace pointer to such a struct,
//   and the OutputSize must match sizeof() the struct.

#define FILEUTIL_IOCTL(FunctionCode)  \
    CTL_CODE( FILEUTIL_TYPE, ( FILEUTIL_FUNCTION_CODE_BASE + FunctionCode ) , METHOD_NEITHER , FILE_ANY_ACCESS  )

#define IOCTL_FILEUTIL_METHOD_GET_ACCESS_INFORMATION FILEUTIL_IOCTL(0)
#define IOCTL_FILEUTIL_METHOD_GET_SHARING_INFORMATION FILEUTIL_IOCTL(1)
#define IOCTL_FILEUTIL_METHOD_GET_CACHING_INFORMATION FILEUTIL_IOCTL(2)


typedef struct _FILEUTIL_ACCESS_INFORMATION {
    UCHAR ReadAccess;
    UCHAR WriteAccess;
    UCHAR DeleteAccess;
} FILEUTIL_ACCESS_INFORMATION, *PFILEUTIL_ACCESS_INFORMATION;

typedef struct _FILEUTIL_SHARING_INFORMATION {
    UCHAR SharedRead;
    UCHAR SharedWrite;
    UCHAR SharedDelete;
} FILEUTIL_SHARING_INFORMATION, *PFILEUTIL_SHARING_INFORMATION;

typedef struct _FILEUTIL_CACHING_INFORMATION {
    UCHAR HasPrivateCache;
    UCHAR HasSharedCache;
    UCHAR HasSectionAsData;
    UCHAR HasSectionAsImage;
} FILEUTIL_CACHING_INFORMATION, *PFILEUTIL_CACHING_INFORMATION;