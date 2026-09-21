#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    poc_print_header("R05", "REMOTE_SERVICE_EXEC");
    printf("\"source_host\":\"ADMIN-01\",\"target_host\":\"SERVER-01\",");
    printf("\"metadata\":{\"service_created\":true,\"service_started\":true,\"remote_target\":true},");
    poc_print_footer();
    return 0;
}
