#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <elf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <cstring>
#include "algorithms.h"

using namespace std;
using json = nlohmann::json;

class MyException {
private:
    std::string reason;
    std::string fname;
    int line;
public:
    MyException(const std::string &reason) : reason(reason), fname(__FILE__), line(__LINE__) {}
    void show() const {
        fprintf(stderr, "%.*s[%d]: %.*s\n", (int)fname.length(), fname.data(), line, (int)reason.length(), reason.data());
    }
};

static int read_data(int fd, void *p, Elf64_Off offset, uint64_t size) {
    lseek(fd, offset, SEEK_SET);
    return (read(fd, p, size)) < size ? -1 : 0;
}

static void *alloc_data(int fd, Elf64_Off offset, size_t num, size_t entsize) {
    void *p = reallocarray(NULL, num, entsize);
    if (p == NULL) {
        return NULL;
    }
    if (read_data(fd, p, offset, num * entsize)) {
        free(p);
        return NULL;
    }
    return p;
}

static void show_hex(char *s, size_t sz) {
    for (int i = 0; i < sz; i++) {
        char c = s[i];
	if (isalnum(c)) {
            printf("%c", c);
        } else {
            printf(".");
        }
	if (i % 64 == 63) {
            printf("\n");
        }
    }
}

static Elf64_Shdr *search_section(Elf64_Shdr *shdr, uint32_t snum, const char *shtab, const char *name) {
    for (int i = 0; i < snum; i++) {
        if (strcmp(name, shtab + shdr[i].sh_name) == 0) {
            return shdr + i;
        }
    }
    return NULL;
}

bool create_libs(ListLib &proc, ListLib &libs, HashPath &cache) {
    bool retcode = false;
    for (ListLibItem &li : proc) {
        // calculate SHA256 for this process
	create_sha256(&li);

        int fd = open((char *)(li.abspath.c_str()), O_RDONLY);
        Elf64_Phdr *ph = NULL;
	Elf64_Shdr *sh = NULL;
	Elf64_Dyn  *dyn = NULL;
	char *shtab = NULL, *dynstr = NULL, *interpstr = NULL;

        try {
            Elf64_Ehdr eh;
            if (fd < 0) throw new MyException(std::string("failed to open ") + li.abspath);
            
            if (read_data(fd, &eh, 0, sizeof(Elf64_Ehdr))) {
                throw new MyException(std::string("illelga header:") + li.abspath);
            }

            // check magic numbers
            if (eh.e_ident[0] != ELFMAG0 || eh.e_ident[1] != ELFMAG1 || eh.e_ident[2] != ELFMAG2 || eh.e_ident[3] != ELFMAG3) {
                throw new MyException(std::string("Illegal MAGIC:") + li.abspath);
            }

            // check AMD X86_64 compatible
            if (eh.e_machine != EM_X86_64) {
                throw new MyException(std::string("Illegal CPU type:") + li.abspath);
            }

            // allocate each tables
            ph = (Elf64_Phdr *)alloc_data(fd, eh.e_phoff, eh.e_phnum, eh.e_phentsize);
            sh = (Elf64_Shdr *)alloc_data(fd, eh.e_shoff, eh.e_shnum, eh.e_shentsize);
            shtab = (char *)alloc_data(fd, sh[eh.e_shstrndx].sh_offset, 1, sh[eh.e_shstrndx].sh_size);

            // search .dynstr section
            Elf64_Shdr *dyn = search_section(sh, eh.e_shnum, shtab, ".dynstr");
            if (dyn != NULL) {
                dynstr = (char *)alloc_data(fd, dyn->sh_offset, 1, dyn->sh_size);
            }

            // search .interp section
            Elf64_Shdr *interp = search_section(sh, eh.e_shnum, shtab, ".interp");
            if (interp != NULL) {
                interpstr = (char *)alloc_data(fd, interp->sh_offset, 1, interp->sh_size);
		string ipstr(interpstr, interp->sh_size);
		register_cache(cache, libs, ipstr, ipstr);
            }

            // search DT_NEEDED item
            for (int j = 0; j < eh.e_shnum; j++) {
                if (sh[j].sh_type == SHT_DYNAMIC) {
                    Elf64_Dyn *pdyn = (Elf64_Dyn *)realloc(nullptr, sh[j].sh_size);
                    if (!pdyn || read_data(fd, pdyn, sh[j].sh_offset, sh[j].sh_size)) {
                        if (pdyn) free(pdyn);
                        throw new MyException(string("failed load library section:") + li.abspath);
                    }
                    Elf64_Dyn *pp = pdyn;
                    while (pp->d_tag != DT_NULL) {
                        if (pp->d_tag == DT_NEEDED && dynstr) {
                            string libname(dynstr + pp->d_un.d_val);
                            auto fi = cache.find(libname);
                            if (fi != cache.end()) {
                                // item found in ldconfig
                                li.libs.push_back(fi->second);
                                if (fi->second->digest.empty()) {
                                    // calculate SHA256 of this dynamic lib if any
                                    create_sha256(fi->second);
                                }
                            }
                        }
                        pp++;
                    }
		    free(pdyn);
                }
            }
            retcode = true;
	} catch (const MyException &exp) {
	    exp.show();
	    fprintf(stderr, "\n");
        }

        if (fd >= 0) close(fd);
	if (ph) free(ph);
	if (sh) free(sh);
	if (dynstr) free(dynstr);
	if (interpstr) free(interpstr);
	if (dyn) free(dyn);
    }

    return retcode;
}
