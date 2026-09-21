#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    poc_print_header("R07", "POWERSHELL_REMOTE");
    printf("\"source_host\":\"ADMIN-01\",\"target_host\":\"SERVER-01\",");
    printf("\"command_line\":\"powershell -e TEST\",");
    printf("\"metadata\":{\"encoded_command_semantics\":true},");
    poc_print_footer();
    return 0;
}
