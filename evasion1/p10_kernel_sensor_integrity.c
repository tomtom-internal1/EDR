#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    const char *poc = "P10_KERNEL_SENSOR_INTEGRITY";
    unsigned long seq = 1;

    poc_emit(poc, seq++, "SensorBaseline", "KERNEL_SENSOR_INTEGRITY",
             "{\"process_callback\":\"present\",\"thread_callback\":\"present\","
             "\"image_callback\":\"present\",\"mode\":\"simulated-baseline\"}");

    poc_emit(poc, seq++, "SensorObservation", "KERNEL_SENSOR_INTEGRITY",
             "{\"event_class\":\"process\",\"observed\":true,\"mode\":\"simulated\"}");

    poc_emit(poc, seq++, "SensorObservation", "KERNEL_SENSOR_INTEGRITY",
             "{\"event_class\":\"thread\",\"observed\":false,\"expected\":true,"
             "\"loss_window_ms\":2500,\"mode\":\"simulated-integrity-gap\"}");

    poc_emit(poc, seq++, "SensorObservation", "KERNEL_SENSOR_INTEGRITY",
             "{\"event_class\":\"image\",\"observed\":true,\"mode\":\"simulated\"}");

    poc_emit(poc, seq++, "DetectionOracle", "KERNEL_SENSOR_INTEGRITY",
             "{\"expected_detection\":\"kernel_telemetry_degradation\","
             "\"root_cause\":\"thread_notification_gap\","
             "\"do_not_conclude_process_idle\":true}");

    poc_emit(poc, seq++, "SensorRecovery", "KERNEL_SENSOR_INTEGRITY",
             "{\"event_class\":\"thread\",\"observed\":true,\"status\":\"restored\","
             "\"kernel_write_performed\":false,\"driver_load_performed\":false}");

    return 0;
}
