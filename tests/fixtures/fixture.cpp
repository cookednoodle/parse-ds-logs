/* Compiled with -g by the test suite.  It gives the tests two things the
 * extractor can be judged against: the layout gcc chose (offsetof and sizeof,
 * reported by the compiler itself) and a filled-in telemetry packet with the
 * values it should decode back to. */
#include "sample_msgs.hpp"

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>

namespace
{

std::string g_layout;
std::string g_expected;
sample::HkTlm_t g_hk;

void add(const char *name, unsigned long offset, unsigned long size)
{
    char line[256];
    std::snprintf(line, sizeof(line), "%s %lu %lu\n", name, offset, size);
    g_layout += line;
}

void expect(const char *name, const char *value)
{
    g_expected += name;
    g_expected += "=";
    g_expected += value;
    g_expected += "\n";
}

void expect_num(const char *name, double value)
{
    char text[64];
    std::snprintf(text, sizeof(text), "%.17g", value);
    expect(name, text);
}

} /* namespace */

#define SIZEOF(T) add("sizeof " #T, 0UL, (unsigned long)sizeof(T))
#define OFFSET(T, M) \
    add("offset " #T "." #M, (unsigned long)offsetof(T, M), (unsigned long)sizeof(((T *)0)->M))

extern "C" const char *dsdecode_layout(void)
{
    if (!g_layout.empty())
    {
        return g_layout.c_str();
    }

    SIZEOF(CCSDS_PrimaryHeader_t);
    SIZEOF(CFE_MSG_Message_t);
    SIZEOF(CFE_MSG_TelemetrySecondaryHeader_t);
    SIZEOF(CFE_MSG_CommandSecondaryHeader_t);
    SIZEOF(CFE_MSG_TelemetryHeader_t);
    SIZEOF(CFE_MSG_CommandHeader_t);
    SIZEOF(CFE_FS_Header_t);
    SIZEOF(DS_FileHeader_t);
    SIZEOF(sample::Vec3);
    SIZEOF(sample::Flags);
    SIZEOF(sample::BaseCounters);
    SIZEOF(sample::HkPayload);
    SIZEOF(sample::HkTlm_t);
    SIZEOF(sample::UnionTlm_t);
    SIZEOF(sample::Value_t);
    SIZEOF(sample::NoopCmd_t);
    SIZEOF(sample::SetModeCmd_t);
    SIZEOF(GLOBAL_Tlm_t);
    SIZEOF(ANON_Tlm_t);
    SIZEOF(PROJ_PRI_HDR_T);
    SIZEOF(PROJ_MSG_TLM_HDR_T);
    SIZEOF(PROJ_Tlm_t);
    SIZEOF(PROJ_Payload_t);
    SIZEOF(PROJ_MSG_CMD_HDR_T);
    SIZEOF(PROJ_NO_ARG_CMD_T);
    SIZEOF(CFE_STYLE_NO_ARG_CMD_T);
    OFFSET(PROJ_MSG_TLM_HDR_T, tSecHdr);
    OFFSET(PROJ_Tlm_t, Counter);
    OFFSET(PROJ_Tlm_t, Words);

    OFFSET(CFE_MSG_TelemetryHeader_t, Msg);
    OFFSET(CFE_MSG_TelemetryHeader_t, Sec);
    OFFSET(CFE_MSG_TelemetryHeader_t, Spare);
    OFFSET(CFE_MSG_CommandHeader_t, Sec);
    OFFSET(CFE_FS_Header_t, Description);
    OFFSET(DS_FileHeader_t, FileTableIndex);
    OFFSET(DS_FileHeader_t, FileName);

    OFFSET(sample::HkTlm_t, TelemetryHeader);
    OFFSET(sample::HkTlm_t, Payload);
    OFFSET(sample::HkPayload, CommandCounter);
    OFFSET(sample::HkPayload, CommandErrorCounter);
    OFFSET(sample::HkPayload, Status);
    OFFSET(sample::HkPayload, Healthy);
    OFFSET(sample::HkPayload, Temperature);
    OFFSET(sample::HkPayload, Uptime);
    OFFSET(sample::HkPayload, Voltage);
    OFFSET(sample::HkPayload, Position);
    OFFSET(sample::HkPayload, Position.y);
    OFFSET(sample::HkPayload, Mode);
    OFFSET(sample::HkPayload, Name);
    OFFSET(sample::HkPayload, Raw);
    OFFSET(sample::HkPayload, Matrix);
    OFFSET(sample::HkPayload, Bias);
    OFFSET(sample::HkPayload, Bits);
    OFFSET(sample::UnionTlm_t, Value);
    OFFSET(sample::UnionTlm_t, Tag);
    OFFSET(sample::SetModeCmd_t, Mode);
    OFFSET(GLOBAL_Tlm_t, Counter);
    OFFSET(GLOBAL_Tlm_t, Words);
    OFFSET(ANON_Tlm_t, Parts);
    OFFSET(ANON_Tlm_t, whole);

    return g_layout.c_str();
}

/* Fill a housekeeping packet with known values and hand back its bytes. */
extern "C" const unsigned char *dsdecode_sample_hk(unsigned long *length)
{
    std::memset(&g_hk, 0, sizeof(g_hk));

    /* CCSDS primary header: telemetry APID 0x090, secondary header present. */
    g_hk.TelemetryHeader.Msg.CCSDS.Pri.StreamId[0] = 0x08;
    g_hk.TelemetryHeader.Msg.CCSDS.Pri.StreamId[1] = 0x90;
    g_hk.TelemetryHeader.Msg.CCSDS.Pri.Sequence[0] = 0xC0; /* unsegmented */
    g_hk.TelemetryHeader.Msg.CCSDS.Pri.Sequence[1] = 0x2A; /* sequence 42 */
    g_hk.TelemetryHeader.Msg.CCSDS.Pri.Length[0]   = (unsigned char)((sizeof(g_hk) - 7) >> 8);
    g_hk.TelemetryHeader.Msg.CCSDS.Pri.Length[1]   = (unsigned char)((sizeof(g_hk) - 7) & 0xFF);

    /* Time: 0x12345678 seconds, 0x8000 subseconds (half a second). */
    g_hk.TelemetryHeader.Sec.Time[0] = 0x12;
    g_hk.TelemetryHeader.Sec.Time[1] = 0x34;
    g_hk.TelemetryHeader.Sec.Time[2] = 0x56;
    g_hk.TelemetryHeader.Sec.Time[3] = 0x78;
    g_hk.TelemetryHeader.Sec.Time[4] = 0x80;
    g_hk.TelemetryHeader.Sec.Time[5] = 0x00;

    g_hk.Payload.CommandCounter      = 11;
    g_hk.Payload.CommandErrorCounter = 4000000000u;
    g_hk.Payload.Status              = 200;
    g_hk.Payload.Healthy             = true;
    g_hk.Payload.Temperature         = -273;
    g_hk.Payload.Uptime              = 0x0102030405060708ull;
    g_hk.Payload.Voltage             = -2.25;
    g_hk.Payload.Position.x          = 1.5f;
    g_hk.Payload.Position.y          = -0.25f;
    g_hk.Payload.Position.z          = 1024.0f;
    g_hk.Payload.Mode                = sample::MODE_SAFE;
    std::strncpy(g_hk.Payload.Name, "hello", sizeof(g_hk.Payload.Name));
    g_hk.Payload.Raw[0] = 0;
    g_hk.Payload.Raw[1] = 127;
    g_hk.Payload.Raw[2] = 128;
    g_hk.Payload.Raw[3] = 255;
    for (int row = 0; row < 2; ++row)
    {
        for (int col = 0; col < 3; ++col)
        {
            g_hk.Payload.Matrix[row][col] = (row * 3 + col) - 3;
        }
    }
    g_hk.Payload.Bias   = -8;
    g_hk.Payload.Bits.a = 1;
    g_hk.Payload.Bits.b = 5;
    g_hk.Payload.Bits.c = 300;

    *length = (unsigned long)sizeof(g_hk);
    return reinterpret_cast<const unsigned char *>(&g_hk);
}

/* The values the packet above must decode back to, named by column. */
extern "C" const char *dsdecode_sample_hk_expected(void)
{
    if (!g_expected.empty())
    {
        return g_expected.c_str();
    }
    unsigned long length = 0;
    dsdecode_sample_hk(&length);

    expect_num("Payload.CommandCounter", g_hk.Payload.CommandCounter);
    expect_num("Payload.CommandErrorCounter", g_hk.Payload.CommandErrorCounter);
    expect_num("Payload.Status", g_hk.Payload.Status);
    expect_num("Payload.Healthy", g_hk.Payload.Healthy ? 1 : 0);
    expect_num("Payload.Temperature", g_hk.Payload.Temperature);
    expect("Payload.Uptime", "72623859790382856");
    expect_num("Payload.Voltage", g_hk.Payload.Voltage);
    expect_num("Payload.Position.x", g_hk.Payload.Position.x);
    expect_num("Payload.Position.y", g_hk.Payload.Position.y);
    expect_num("Payload.Position.z", g_hk.Payload.Position.z);
    expect("Payload.Mode", "MODE_SAFE");
    expect("Payload.Name", "hello");
    expect_num("Payload.Raw[0]", g_hk.Payload.Raw[0]);
    expect_num("Payload.Raw[1]", g_hk.Payload.Raw[1]);
    expect_num("Payload.Raw[2]", g_hk.Payload.Raw[2]);
    expect_num("Payload.Raw[3]", g_hk.Payload.Raw[3]);
    for (int row = 0; row < 2; ++row)
    {
        for (int col = 0; col < 3; ++col)
        {
            char name[64];
            std::snprintf(name, sizeof(name), "Payload.Matrix[%d][%d]", row, col);
            expect_num(name, g_hk.Payload.Matrix[row][col]);
        }
    }
    expect_num("Payload.Bias", g_hk.Payload.Bias);
    expect_num("Payload.Bits.a", g_hk.Payload.Bits.a);
    expect_num("Payload.Bits.b", g_hk.Payload.Bits.b);
    expect_num("Payload.Bits.c", g_hk.Payload.Bits.c);
    return g_expected.c_str();
}

/* Force the compiler to emit debug info for every type of interest. */
extern "C" void dsdecode_instantiate(void)
{
    static sample::HkTlm_t      hk;
    static sample::UnionTlm_t   uni;
    static sample::NoopCmd_t    noop;
    static sample::SetModeCmd_t set_mode;
    static GLOBAL_Tlm_t         global_tlm;
    static ANON_Tlm_t           anon_tlm;
    static PROJ_Tlm_t           proj_tlm;
    static PROJ_Payload_t       proj_payload;
    static PROJ_NO_ARG_CMD_T    proj_no_arg;
    static CFE_STYLE_NO_ARG_CMD_T cfe_no_arg;
    static CFE_FS_Header_t      fs_header;
    static DS_FileHeader_t      ds_header;
    (void)hk;
    (void)uni;
    (void)noop;
    (void)set_mode;
    (void)global_tlm;
    (void)anon_tlm;
    (void)proj_tlm;
    (void)proj_payload;
    (void)proj_no_arg;
    (void)cfe_no_arg;
    (void)fs_header;
    (void)ds_header;
}
