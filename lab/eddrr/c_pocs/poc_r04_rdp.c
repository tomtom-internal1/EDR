#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    poc_print_header("R04", "RDP_REMOTE_SESSION");
    printf("\"source_host\":\"LAPTOP-01\",\"target_host\":\"SERVER-01\",");
    printf("\"protocol\":\"RDP\",\"session_id\":\"SIM-04\",");
    printf("\"metadata\":{\"interactive_logon\":true,\"approved_user\":true,\"after_hours\":true},");
    poc_print_footer();
    return 0;
}
