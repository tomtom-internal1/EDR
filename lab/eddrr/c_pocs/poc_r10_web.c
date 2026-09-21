#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    poc_print_header("R10", "WEB_C2_SIM");
    printf("\"source_host\":\"WORKSTATION-01\",\"target_host\":\"WEB-01\",");
    printf("\"protocol\":\"HTTP\",\"destination_port\":443,");
    printf("\"metadata\":{\"user_agent\":\"Mozilla/5.0\",\"periodic\":true,\"small_response\":true},");
    poc_print_footer();
    return 0;
}
