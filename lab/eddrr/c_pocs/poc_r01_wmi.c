#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    poc_print_header("R01", "WMI_REMOTE_EXEC");
    printf("\"source_host\":\"ADMIN-01\",\"target_host\":\"SERVER-01\",");
    printf("\"protocol\":\"WMI\",\"metadata\":{\"local_process_created\":false,\"remote_process_created\":true},");
    poc_print_footer();
    return 0;
}
