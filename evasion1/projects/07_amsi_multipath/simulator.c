/*
 * A07 deterministic telemetry simulator.
 *
 * This file deliberately does not call AMSI, modify process memory,
 * or interact with a security product. It exists as a positive/negative
 * control for EDR correlation and regression testing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define DEFAULT_REPEATS 3U
#define MAX_REPEATS 100U

static unsigned long long now_ms(void)
{
    return (unsigned long long)time(NULL) * 1000ULL;
}

static void emit(unsigned long seq, const char *event_type,
                 const char *technique, const char *details)
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
            printf("A07 simulator scenarios: stable, result-flip, "
                   "hresult-failure, cross-path-drift\n");
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
         "\"source\":\"A07_deterministic_control\"}");

    unsigned int result_changes = 0;
    unsigned int hresult_failures = 0;

    for (unsigned int round = 1; round <= repeats; ++round) {
        const char *buffer_result = "CLEAN";
        const char *string_result = "CLEAN";
        const char *buffer_hr = "0x00000000";
        const char *string_hr = "0x00000000";

        if (is_mode(scenario, "result-flip") && round > 1) {
            buffer_result = "DETECTED";
            result_changes++;
        }

        if (is_mode(scenario, "hresult-failure") && round == 2) {
            buffer_hr = "0x80004005";
            hresult_failures++;
        }

        if (is_mode(scenario, "cross-path-drift") && round > 1) {
            string_result = "NOT_DETECTED";
            result_changes++;
        }

        char details[768];

        snprintf(details, sizeof(details),
                 "{\"method\":\"AmsiScanString\",\"session\":\"session\","
                 "\"input\":\"synthetic_benign\",\"hresult\":\"%s\","
                 "\"hresult_success\":%s,\"result_name\":\"%s\","
                 "\"result_is_malware\":false,\"simulation\":true,"
                 "\"round\":%u}",
                 string_hr,
                 strcmp(string_hr, "0x00000000") == 0 ? "true" : "false",
                 string_result, round);

        emit(10 + ((round - 1) * 2), "AmsiScan",
             "AMSI_MULTIPATH_VALIDATION", details);

        snprintf(details, sizeof(details),
                 "{\"method\":\"AmsiScanBuffer\",\"session\":\"session\","
                 "\"input\":\"synthetic_benign\",\"hresult\":\"%s\","
                 "\"hresult_success\":%s,\"result_name\":\"%s\","
                 "\"result_is_malware\":%s,\"simulation\":true,"
                 "\"round\":%u}",
                 buffer_hr,
                 strcmp(buffer_hr, "0x00000000") == 0 ? "true" : "false",
                 buffer_result,
                 strcmp(buffer_result, "DETECTED") == 0 ? "true" : "false",
                 round);

        emit(11 + ((round - 1) * 2), "AmsiScan",
             "AMSI_MULTIPATH_VALIDATION", details);
    }

    {
        char details[512];
        snprintf(details, sizeof(details),
                 "{\"simulation\":true,\"scenario\":\"%s\","
                 "\"repeat_count\":%u,\"path_result_changes\":%u,"
                 "\"hresult_failures\":%u}",
                 scenario, repeats, result_changes, hresult_failures);
        emit(100, "CrossPathCorrelation",
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
                 "\"oracle\":\"hresult_failures_or_result_changes\"}",
                 status, scenario);

        emit(101, "DetectionOracle",
             "AMSI_MULTIPATH_VALIDATION", details);
    }

    return 0;
}
