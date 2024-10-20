#include "algorithms.h"
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char **argv) {
    char *prop = NULL;
    if (argc > 1) {
        prop = argv[1];
    }
    time_t t = time(nullptr);
    struct tm *tm = localtime(&t);
    char tstr[64];
    strftime(tstr, sizeof(tstr), "%Y-%m-%d %H:%M:%s", tm);

    fprintf(stderr, "%s started at %s\n", argv[0], tstr);
    return run(std::string(prop ? prop : ""));
}
