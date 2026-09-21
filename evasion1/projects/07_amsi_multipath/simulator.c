/*
 * A07 deterministic telemetry simulator.
 *
 * Deliberately does not call AMSI, modify process memory, or interact
 * with security products. It is a deterministic positive/negative
 * control for EDR correlation and regression testing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_REPEATS 3U
#define MAX_REPEATS 100U

static unsigned long long now_ms(void)
{
    return (unsigned long long)time(NULL) * 1000ULL;
}

static void emit(unsigned long seq,
                 const char *event_type,
                 const char *technique,
                 const char *details)
{
    printf("{\"poc_id\":\"A07_AMSI_MULTIPATH\","
           "\"sequence\":%lu,\"timestamp_ms\":%llu,"
           "\"pid\":0,\"tid\":0,\"event_type\":\"%s\","
           "\"technique\":\"%s\",\"details\":%s}\n",
           seq, now_ms(), event_type, technique,
           details ? details : "{}");
}

static unsigned int parse_u32(const char *s, unsigned int max)
{
    char *end = NULL;
    unsigned long v;

    if (!s || !*s) return 0;
    v = strtoul(s, &end, 10);
    if (*end != '\0' || v == 0 || v > max) return 0;
    return (unsigned int)v;
}

static int is_mode(const char *mode, const char *expected)
{
    return strcmp(mode, expected) == 0;
}

static void emit_scan(unsigned long seq,
                      unsigned int round,
                      const char *method,
                      const char *session,
                      const char *result,
                      const char *hr,
                      int malware)
{
    char details[768];

    snprintf(details, sizeof(details),
             "{\"method\":\"%s\",\"session\":\"%s\","
             "\"input\":\"synthetic_benign\","
             "\"hresult\":\"%s\",\"hresult_success\":%s,"
             "\"result_name\":\"%s\",\"result_is_malware\":%s,"
             "\"simulation\":true,\"round\":%u}",
             method,
             session,
             hr,
             strcmp(hr, "0x00000000") == 0 ? "true" : "false",
             result,
             malware ? "true" : "false",
             round);

    emit(seq, "AmsiScan", "AMSI_MULTIPATH_VALIDATION", details);
}

int main(int argc, char **argv)
{
    const char *scenario = "stable";
    unsigned int repeats = DEFAULT_REPEATS;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--scenario") == 0 && i + 1 < argc) {
            scenario = argv[++i];
        } else if (strcmp(argv[i], "--repeat") == 0 && i + 1 < argc) {
            repeats = parse_u32(argv[++i], MAX_REPEATS);
            if (repeats == 0) {
                fprintf(stderr, "invalid --repeat\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--help") == 0) {
            puts("A07 simulator scenarios: stable, result-flip, "
                 "hresult-failure, cross-path-drift");
            return 0;
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return 2;
        }
    }

    if (!is_mode(scenario, "stable") &&
        !is_mode(scenario, "result-flip") &&
        !is_mode(scenario, "hresult-failure") &&
        !is_mode(scenario, "cross-path-drift")) {
        fprintf(stderr, "unknown scenario: %s\n", scenario);
        return 2;
    }

    emit(1, "SimulationContext", "AMSI_MULTIPATH_VALIDATION",
         "{\"simulation\":true,\"input\":\"synthetic_benign\","
         "\"source\":\"A07_deterministic_control\","
         "\"matrix\":\"string_session,string_no_session,"
         "buffer_session,buffer_no_session\"}");

    unsigned int result_changes = 0;
    unsigned int hresult_failures = 0;

    for (unsigned int round = 1; round <= repeats; ++round) {
        const char *ss_result = "CLEAN";
        const char *sn_result = "CLEAN";
        const char *bs_result = "CLEAN";
        const char *bn_result = "CLEAN";

        const char *ss_hr = "0x00000000";
        const char *sn_hr = "0x00000000";
        const char *bs_hr = "0x00000000";
        const char *bn_hr = "0x00000000";

        if (is_mode(scenario, "result-flip") && round > 1) {
            bs_result = "DETECTED";
            result_changes++;
        }

        if (is_mode(scenario, "hresult-failure") && round == 2) {
            bn_hr = "0x80004005";
            hresult_failures++;
        }

        if (is_mode(scenario, "cross-path-drift") && round > 1) {
            sn_result = "NOT_DETECTED";
            result_changes++;
        }

        emit_scan(10 + ((round - 1) * 4), round,
                  "AmsiScanString", "session",
                  ss_result, ss_hr, 0);

        emit_scan(11 + ((round - 1) * 4), round,
                  "AmsiScanString", "no_session",
                  sn_result, sn_hr, 0);

        emit_scan(12 + ((round - 1) * 4), round,
                  "AmsiScanBuffer", "session",
                  bs_result, bs_hr,
                  strcmp(bs_result, "DETECTED") == 0);

        emit_scan(13 + ((round - 1) * 4), round,
                  "AmsiScanBuffer", "no_session",
                  bn_result, bn_hr, 0);
    }

    emit(100, "AmsiNotifyOperation",
         "AMSI_MULTIPATH_VALIDATION",
         "{\"simulation\":true,\"notify_success\":true}");

    {
        char details[640];

        snprintf(details, sizeof(details),
                 "{\"simulation\":true,\"scenario\":\"%s\","
                 "\"repeat_count\":%u,\"path_result_changes\":%u,"
                 "\"hresult_failures\":%u,"
                 "\"matrix\":\"string_session,string_no_session,"
                 "buffer_session,buffer_no_session\"}",
                 scenario,
                 repeats,
                 result_changes,
                 hresult_failures);

        emit(101, "CrossPathCorrelation",
             "AMSI_MULTIPATH_VALIDATION", details);
    }

    {
        const char *status =
            (result_changes == 0 && hresult_failures == 0)
                ? "STABLE" : "ANOMALY";

        char details[640];

        snprintf(details, sizeof(details),
                 "{\"simulation\":true,\"status\":\"%s\","
                 "\"scenario\":\"%s\","
                 "\"oracle\":\"hresult_failures_or_result_changes\","
                 "\"native_amsi_not_invoked\":true}",
                 status, scenario);

        emit(102, "DetectionOracle",
             "AMSI_MULTIPATH_VALIDATION", details);
    }

    return 0;
}
