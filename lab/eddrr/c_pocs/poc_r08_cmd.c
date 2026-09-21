#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    poc_print_header("R08", "CMD_REMOTE");
    printf("\"source_host\":\"ADMIN-01\",\"target_host\":\"SERVER-01\",");
    printf("\"command_line\":\"CMD.EXE /C whoami\",");
    poc_print_footer();
    return 0;
}
