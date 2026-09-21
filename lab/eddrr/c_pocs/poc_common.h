#ifndef EDDRR_POC_COMMON_H
#define EDDRR_POC_COMMON_H

#include <stdio.h>

static void poc_print_header(const char *id, const char *technique)
{
    printf("{\"event_type\":\"RemoteSimulation\",\"poc_id\":\"%s\",\"technique\":\"%s\",", id, technique);
}

static void poc_print_footer(void)
{
    printf("\"synthetic\":true}\n");
}

#endif
