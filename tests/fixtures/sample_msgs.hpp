/* Message payloads exercising the C++ shapes flight apps actually use:
 * namespaces, inheritance, nested structs, multi-dimensional arrays, enums,
 * bitfields, unions, anonymous members and every scalar width. */
#ifndef DSDECODE_SAMPLE_MSGS_HPP
#define DSDECODE_SAMPLE_MSGS_HPP

#include "cfe_msg_mini.h"

namespace sample
{

enum Mode_t
{
    MODE_IDLE = 0,
    MODE_RUN  = 1,
    MODE_SAFE = 7
};

struct Vec3
{
    float x;
    float y;
    float z;
};

struct Flags
{
    uint8  a : 1;
    uint8  b : 3;
    uint16 c : 9;
};

struct BaseCounters
{
    uint32 CommandCounter;
    uint32 CommandErrorCounter;
};

struct HkPayload : public BaseCounters
{
    uint8  Status;
    bool   Healthy;
    int16  Temperature;
    uint64 Uptime;
    double Voltage;
    Vec3   Position;
    Mode_t Mode;
    char   Name[12];
    uint8  Raw[4];
    int32  Matrix[2][3];
    int8   Bias;
    Flags  Bits;
};

struct HkTlm_t
{
    CFE_MSG_TelemetryHeader_t TelemetryHeader;
    HkPayload                 Payload;
};

union Value_t
{
    int32 i;
    float f;
    uint8 b[4];
};

struct UnionTlm_t
{
    CFE_MSG_TelemetryHeader_t TelemetryHeader;
    Value_t                   Value;
    uint32                    Tag;
};

struct NoopCmd_t
{
    CFE_MSG_CommandHeader_t CommandHeader;
};

struct SetModeCmd_t
{
    CFE_MSG_CommandHeader_t CommandHeader;
    uint32                  Mode;
};

} /* namespace sample */

/* A plain C style message, the shape most cFS apps use. */
typedef struct
{
    CFE_MSG_TelemetryHeader_t TelemetryHeader;
    uint32                    Counter;
    uint16                    Words[3];
} GLOBAL_Tlm_t;

/* Anonymous struct and union members, which flatten into the parent. */
typedef struct
{
    CFE_MSG_TelemetryHeader_t TelemetryHeader;
    struct
    {
        uint16 lo;
        uint16 hi;
    } Parts;
    union
    {
        uint32 whole;
        uint8  bytes[4];
    };
} ANON_Tlm_t;

/* A project that defines its own header types rather than using the cFE ones,
 * then gives them cFE looking names.  The structs are wire compatible with cFE
 * by hand, not by any compiler enforced link, and this one has no trailing
 * Spare, so it is 12 bytes where the cFE telemetry header is 16.  Nothing here
 * carries a name the decoder knows, which is the point. */
typedef struct
{
    uint8 StreamId[2];
    uint8 Sequence[2];
    uint8 Length[2];
} PROJ_PRI_HDR_T;

typedef struct
{
    uint8 iTime[6];
} PROJ_TLM_SEC_HDR_T;

typedef struct
{
    PROJ_PRI_HDR_T     tPriHdr;
    PROJ_TLM_SEC_HDR_T tSecHdr;
} PROJ_MSG_TLM_HDR_T;

/* Named to look like cFE, but a typedef of the project's own struct. */
typedef PROJ_MSG_TLM_HDR_T CFE_MSG_TLM_HDR_T;

typedef struct
{
    CFE_MSG_TLM_HDR_T TlmHeader;
    uint32            Counter;
    uint16            Words[3];
} PROJ_Tlm_t;

/* A payload with no header at all, whose first three fields are two bytes
 * each.  Guards against anything that tries to spot a header by its shape. */
typedef struct
{
    uint16 First;
    uint16 Second;
    uint16 Third;
    uint32 Rest;
} PROJ_Payload_t;

#endif /* DSDECODE_SAMPLE_MSGS_HPP */
