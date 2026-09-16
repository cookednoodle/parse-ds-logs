/* A cut-down copy of the cFE 7.x (Caelum) message and file headers, laid out
 * exactly as cFE lays them out for CCSDS version 1 on a little-endian target.
 * The tests compile this so the extractor can be checked against real gcc
 * output without a full cFS tree. */
#ifndef DSDECODE_CFE_MSG_MINI_H
#define DSDECODE_CFE_MSG_MINI_H

typedef unsigned char      uint8;
typedef signed char        int8;
typedef unsigned short     uint16;
typedef short              int16;
typedef unsigned int       uint32;
typedef int                int32;
typedef unsigned long long uint64;
typedef long long          int64;

typedef struct
{
    uint8 StreamId[2]; /* big endian: version, type, sec hdr flag, APID */
    uint8 Sequence[2]; /* big endian: sequence flags and count */
    uint8 Length[2];   /* big endian: total packet length minus 7 */
} CCSDS_PrimaryHeader_t;

typedef struct
{
    CCSDS_PrimaryHeader_t Pri;
} CCSDS_SpacePacket_t;

union CFE_MSG_Message
{
    CCSDS_SpacePacket_t CCSDS;
    uint8               Byte[sizeof(CCSDS_SpacePacket_t)];
};
typedef union CFE_MSG_Message CFE_MSG_Message_t;

typedef struct
{
    uint8 Time[6]; /* big endian: 4 byte seconds, 2 byte subseconds */
} CFE_MSG_TelemetrySecondaryHeader_t;

typedef struct
{
    uint8 FunctionCode;
    uint8 Checksum;
} CFE_MSG_CommandSecondaryHeader_t;

struct CFE_MSG_TelemetryHeader
{
    CFE_MSG_Message_t                  Msg;
    CFE_MSG_TelemetrySecondaryHeader_t Sec;
    uint8                              Spare[4];
};
typedef struct CFE_MSG_TelemetryHeader CFE_MSG_TelemetryHeader_t;

struct CFE_MSG_CommandHeader
{
    CFE_MSG_Message_t                Msg;
    CFE_MSG_CommandSecondaryHeader_t Sec;
};
typedef struct CFE_MSG_CommandHeader CFE_MSG_CommandHeader_t;

#define CFE_FS_HDR_DESC_MAX_LEN 32

typedef struct CFE_FS_Header
{
    uint32 ContentType;
    uint32 SubType;
    uint32 Length;
    uint32 SpacecraftID;
    uint32 ProcessorID;
    uint32 ApplicationID;
    uint32 TimeSeconds;
    uint32 TimeSubSeconds;
    char   Description[CFE_FS_HDR_DESC_MAX_LEN];
} CFE_FS_Header_t;

#define DS_TOTAL_FNAME_BUFSIZE 64

typedef struct
{
    uint32 CloseSeconds;
    uint32 CloseSubsecs;
    uint16 FileTableIndex;
    uint16 FileNameType;
    char   FileName[DS_TOTAL_FNAME_BUFSIZE];
} DS_FileHeader_t;

#endif /* DSDECODE_CFE_MSG_MINI_H */
