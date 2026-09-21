#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    poc_print_header("R02", "WINRM_REMOTE_EXEC");
    printf("\"source_host\":\"ADMIN-01\",\"target_host\":\"SERVER-01\",");
    printf("\"protocol\":\"WinRM\",\"destination_port\":5986,");
    printf("\"metadata\":{\"remote_command_result\":\"simulated\"},");
    poc_print_footer();
    return 0;
}
