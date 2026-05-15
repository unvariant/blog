// Based off of `sioctl.c` driver example in the WDK

//
// Include files.
//

#include <ntddk.h>          // various NT definitions
#include <string.h>
#include "interface.h"



#define DRIVER_FUNC_INSTALL     0x01
#define DRIVER_FUNC_REMOVE      0x02

#define DRIVER_NAME       "FileUtilityDriver"

#define NT_DEVICE_NAME      L"\\Device\\FileUtility"
#define DOS_DEVICE_NAME     L"\\DosDevices\\FileUtility"

#if DBG
#define FILEUTIL_KDPRINT(_x_) \
                DbgPrint("FileUtil: ");\
                DbgPrint _x_;

#else
#define FILEUTIL_KDPRINT(_x_)
#endif

//
// Device driver routine declarations.
//

DRIVER_INITIALIZE DriverEntry;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH FileUtilityCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH FileUtilityDeviceControl;

DRIVER_UNLOAD FileUtilityUnloadDriver;

VOID
PrintIrpInfo(
    PIRP Irp
);
VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, FileUtilityCreateClose)
#pragma alloc_text( PAGE, FileUtilityDeviceControl)
#pragma alloc_text( PAGE, FileUtilityUnloadDriver)
#pragma alloc_text( PAGE, PrintIrpInfo)
#pragma alloc_text( PAGE, PrintChars)
#endif // ALLOC_PRAGMA


NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING      RegistryPath
)
/*++

Routine Description:
    This routine is called by the Operating System to initialize the driver.

    It creates the device object, fills in the dispatch entry points and
    completes the initialization.

Arguments:
    DriverObject - a pointer to the object that represents this device
    driver.

    RegistryPath - a pointer to our Services key in the registry.

Return Value:
    STATUS_SUCCESS if initialized; an error otherwise.

--*/

{
    NTSTATUS        ntStatus;
    UNICODE_STRING  ntUnicodeString;    // NT Device Name "\Device\FileUtility"
    UNICODE_STRING  ntWin32NameString;    // Win32 Name "\DosDevices\FileUtility"
    PDEVICE_OBJECT  deviceObject = NULL;    // ptr to device object

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&ntUnicodeString, NT_DEVICE_NAME);

    ntStatus = IoCreateDevice(
        DriverObject,                   // Our Driver Object
        0,                              // We don't use a device extension
        &ntUnicodeString,               // Device name "\Device\FileUtility"
        FILE_DEVICE_UNKNOWN,            // Device type
        FILE_DEVICE_SECURE_OPEN,     // Device characteristics
        FALSE,                          // Not an exclusive device
        &deviceObject);                // Returned ptr to Device Object

    if (!NT_SUCCESS(ntStatus))
    {
        FILEUTIL_KDPRINT(("Couldn't create the device object\n"));
        return ntStatus;
    }

    //
    // Initialize the driver object with this driver's entry points.
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE] = FileUtilityCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = FileUtilityCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FileUtilityDeviceControl;
    DriverObject->DriverUnload = FileUtilityUnloadDriver;

    //
    // Initialize a Unicode String containing the Win32 name
    // for our device.
    //

    RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);

    //
    // Create a symbolic link between our device name  and the Win32 name
    //

    ntStatus = IoCreateSymbolicLink(
        &ntWin32NameString, &ntUnicodeString);

    if (!NT_SUCCESS(ntStatus))
    {
        //
        // Delete everything that this routine has allocated.
        //
        FILEUTIL_KDPRINT(("Couldn't create symbolic link\n"));
        IoDeleteDevice(deviceObject);
    }


    return ntStatus;
}


NTSTATUS
FileUtilityCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++

Routine Description:

    This routine is called by the I/O system when the FILEUTIL is opened or
    closed.

    No action is performed other than completing the request successfully.

Arguments:

    DeviceObject - a pointer to the object that represents the device
    that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/

{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

VOID
FileUtilityUnloadDriver(
    _In_ PDRIVER_OBJECT DriverObject
)
/*++

Routine Description:

    This routine is called by the I/O system to unload the driver.

    Any resources previously allocated must be freed.

Arguments:

    DriverObject - a pointer to the object that represents our driver.

Return Value:

    None
--*/

{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING uniWin32NameString;

    PAGED_CODE();

    //
    // Create counted string version of our Win32 device name.
    //

    RtlInitUnicodeString(&uniWin32NameString, DOS_DEVICE_NAME);


    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //

    IoDeleteSymbolicLink(&uniWin32NameString);

    if (deviceObject != NULL)
    {
        IoDeleteDevice(deviceObject);
    }



}

NTSTATUS
FileUtilityDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)

/*++

Routine Description:

    This routine is called by the I/O system to perform a device I/O
    control function.

Arguments:

    DeviceObject - a pointer to the object that represents the device
        that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/

{
    PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
    NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
    ULONG               inBufLength; // Input buffer length
    ULONG               outBufLength; // Output buffer length

 
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    // OutputBuffer must be present and point to userspace, size needs to be checked by each handler individually to match the desired struct
    if (!Irp->UserBuffer || (INT64)Irp->UserBuffer < 0) {
        ntStatus = STATUS_INVALID_PARAMETER;
        goto End;
    }


    // We know that InputBuffer is a file handle for all handlers. Fetch the actual object now
    if (inBufLength) {
        ntStatus = STATUS_INVALID_PARAMETER;
        goto End;
    }

    HANDLE fileHandle = (HANDLE)irpSp->Parameters.DeviceIoControl.Type3InputBuffer;

    PFILE_OBJECT fileObject;
    ntStatus = ObReferenceObjectByHandle(fileHandle, FILE_READ_ACCESS, *IoFileObjectType, UserMode, (PVOID*)&fileObject, NULL);
    if (!NT_SUCCESS(ntStatus)) goto End;

#define CHECK_AND_CAST_OUTPUT(name, type) \
    if (outBufLength != sizeof(type)) { \
        ntStatus = STATUS_INFO_LENGTH_MISMATCH; \
        ObDereferenceObject(fileHandle); \
        goto End; \
    } \
    type* name = (type*) Irp->UserBuffer; \
    memset(name, 0, sizeof(type))

    //
    // Determine which I/O control code was specified.
    //
    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_FILEUTIL_METHOD_GET_ACCESS_INFORMATION: {
        CHECK_AND_CAST_OUTPUT(info, FILEUTIL_ACCESS_INFORMATION);

        info->ReadAccess = fileObject->ReadAccess;
        info->WriteAccess = fileObject->WriteAccess;
        info->DeleteAccess = fileObject->DeleteAccess;
        ObDereferenceObject(fileObject);
    }
    case IOCTL_FILEUTIL_METHOD_GET_SHARING_INFORMATION: {
        CHECK_AND_CAST_OUTPUT(info, FILEUTIL_SHARING_INFORMATION);
        info->SharedRead = fileObject->SharedRead;
        info->SharedWrite = fileObject->SharedWrite;
        info->SharedDelete = fileObject->SharedDelete;

        ObDereferenceObject(fileObject);
        break;
    }
    case IOCTL_FILEUTIL_METHOD_GET_CACHING_INFORMATION: {
        CHECK_AND_CAST_OUTPUT(info, FILEUTIL_CACHING_INFORMATION);

        info->HasPrivateCache = !!fileObject->PrivateCacheMap;
        if (fileObject->SectionObjectPointer) {
            info->HasSectionAsData = !!fileObject->SectionObjectPointer->DataSectionObject;
            info->HasSharedCache = !!fileObject->SectionObjectPointer->SharedCacheMap;
            info->HasSectionAsImage = !!fileObject->SectionObjectPointer->ImageSectionObject;
        }
        ObDereferenceObject(fileObject);
        break;
    }
    default:

        //
        // The specified I/O control code is unrecognized by this driver.
        //

        ntStatus = STATUS_INVALID_DEVICE_REQUEST;
        FILEUTIL_KDPRINT(("ERROR: unrecognized IOCTL %x\n",
            irpSp->Parameters.DeviceIoControl.IoControlCode));
        ObDereferenceObject(fileObject);
        break;
    }

End:
    //
    // Finish the I/O operation by simply completing the packet and returning
    // the same status as in the packet itself.
    //

    Irp->IoStatus.Status = ntStatus;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return ntStatus;
}
