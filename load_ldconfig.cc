#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include <regex.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include "algorithms.h"

using namespace std;

bool load_ldconfig(ListLib &libs, HashPath &cache) {
    FILE *f = popen("/sbin/ldconfig -p", "r");
    size_t sz = PATH_MAX;
    char *s = (char *)malloc(sz);
    regex_t regt;
    regmatch_t match[3];

    if (f == NULL) {
        perror("popen");
        return false;
    }
    if (regcomp(&regt, "(\\S+)\\s+.*\\s+=>\\s+(\\S+)", REG_EXTENDED)) {
        perror("regcomp");
	return false;
    }
    while (fgets(s, sz, f)) {
        if (regexec(&regt, s, 3, &match[0], 0) == 0 && match[1].rm_so >= 0 && match[2].rm_so >= 0) {
            std::string q(s + match[1].rm_so, match[1].rm_eo - match[1].rm_so);
            std::string p(s + match[2].rm_so, match[2].rm_eo - match[2].rm_so);
            register_cache(cache, libs, q, p);
        }
    }
    regfree(&regt);
    pclose(f);
    return true;
}

static char *trace_symlink(char *p) {
    char *s = (char *)malloc(PATH_MAX);
    ssize_t ssz = readlink(p, s, PATH_MAX);
    if (ssz < 0) {
        free(s);
	return NULL;
    }
    s[ssz] = '\0';
    return s;
}

bool get_proclist(ListLib &proc, HashPath &cache) {
    regex_t regt;
    DIR *de = opendir("/proc");
    struct dirent *dent;
    if (regcomp(&regt, "[0-9]+", REG_EXTENDED)) {
        perror("regcomp");
	closedir(de);
	return false;
    }
    while ((dent = readdir(de)) != NULL) {
        regmatch_t pmatch[1];
        if (regexec(&regt, &dent->d_name[0], 1, &pmatch[0], 0) == 0) {
            char exe[32];
            char *tlink;
	    snprintf(exe, sizeof(exe), "/proc/%.*s/exe", pmatch[0].rm_eo - pmatch[0].rm_so, &dent->d_name[pmatch[0].rm_so]);
            tlink = trace_symlink(exe);
            if (tlink) {
                std::string s(tlink);
		if (cache.find(s) == cache.end()) {
                    register_cache(cache, proc, s, s);
		    ListLibItem &li = proc.back();
		    li.pid = (pid_t)(int)atoi(dent->d_name);
		    li.abspath = s;
                }
                free(tlink);
            }
        }
    }
    closedir(de);
    regfree(&regt);
    return true;
}
