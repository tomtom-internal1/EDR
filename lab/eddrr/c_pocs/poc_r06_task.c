#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    poc_print_header("R06", "REMOTE_SCHEDULED_TASK");
    printf("\"source_host\":\"ADMIN-01\",\"target_host\":\"SERVER-01\",");
    printf("\"metadata\":{\"remote_task_created\":true},");
    poc_print_footer();
    return 0;
}
