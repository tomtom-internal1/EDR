#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    poc_print_header("R09", "REMOTE_TRANSFER");
    printf("\"source_host\":\"ADMIN-01\",\"target_host\":\"SERVER-01\",");
    printf("\"metadata\":{\"filename\":\"diagnostic.bin\",\"content_type\":\"application/x-binary\"},");
    poc_print_footer();
    return 0;
}
