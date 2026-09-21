#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    poc_print_header("R03", "SMB_ADMIN_SHARE");
    printf("\"source_host\":\"ADMIN-01\",\"target_host\":\"SERVER-01\",");
    printf("\"protocol\":\"SMB\",\"destination_port\":445,");
    printf("\"metadata\":{\"share_connection_only\":true,\"file_write_after_share\":false},");
    poc_print_footer();
    return 0;
}
