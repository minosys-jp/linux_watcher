#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <regex.h>
#include <openssl/evp.h>
#include <fstream>
#include "algorithms.h"
#include <vector>

ListLib list_proc, list_lib;
HashPath path_cache;
OrderCache order_cache;
Property properties;

using namespace std;
using json = nlohmann::json;

static string toHex(unsigned char *s, unsigned int len) {
    const unsigned char cc[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    string st;
    for (int i = 0;  i < len; i++) {
        st += cc[(s[i] >> 4) & 15];
	st += cc[s[i] & 15];
    }
    return st;
};

struct MyShaException {
    string message;
    MyShaException(const string &s) : message(s) {}
};

void create_sha256(ListLibItem *pi) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_get_digestbyname("SHA256");
    char *s = nullptr;

    try {
        if (!EVP_DigestInit_ex(ctx, md, nullptr)) {
            throw new MyShaException("EVP_DigestInit_ex2");
        }
        ifstream ifs(pi->abspath);
        s = new char[PATH_MAX];
        size_t count = 0;
        unsigned char hash_sha256[32];
        unsigned int hash_size;

        do {
            ifs.read(s, PATH_MAX);
	    count = ifs.gcount();
	    if (!EVP_DigestUpdate(ctx, s, count)) {
                throw new MyShaException("EVP_DigestUpdate");
            }
        } while(!ifs.eof() && !ifs.fail());
        if (!EVP_DigestFinal_ex(ctx, hash_sha256, &hash_size)) {
            throw new MyShaException("EVP_DigestFinal_ex");
        }
        pi->digest = toHex(hash_sha256, hash_size);
    } catch (const MyShaException ex) {
        fprintf(stderr, "Error in %s", ex.message.c_str());
    }
    if (s) delete[] s;
    if (ctx) EVP_MD_CTX_free(ctx);
}

int numbering(ListLib &lib, int start) {
    int count = start;
    for (ListLibItem &i : lib) {
        order_cache.insert(pair<int, ListLibItem *>(count, &i));
        i.order = count++;
    }
    return count;
}

bool create_json(json &v, const ListLib &proc, const ListLib &libs) {
    v.clear();
    auto itenant = properties.find("tenant");
    auto idomain = properties.find("domain");
    if (itenant == properties.cend() || idomain == properties.cend()) {
        fprintf(stderr, "failed to find 'tenant' and 'domain'\n");
	return false;
    }
    string tenant = itenant->second;
    string domain = idomain->second;
    auto ihostname = properties.find("hostname");
    string host;
    if (ihostname == properties.cend()) {
      char hostname[HOST_NAME_MAX];
      if (gethostname(hostname, sizeof(hostname)) < 0) {
          fprintf(stderr, "failed to find hostname");
          return false;
      }
      host = hostname;
    } else {
      host = ihostname->second;
    }

    // global properties
    v["tenant"] = tenant;
    v["domain"] = domain;
    v["hostname"] = host;
    auto ipublish = properties.find("publish");
    int publish = false;
    if (ipublish != properties.cend()) {
        publish = (ipublish->second == "true") ? 1 : 0;
    }
    v["flg_publish"] = publish;

    // processes and libraries fingers
    int count = 0;
    for (const ListLibItem &iproc : proc) {
        v["fingers"][count]["dbid"] = iproc.order;
	v["fingers"][count]["name"] = iproc.abspath;
	v["fingers"][count]["finger"] = iproc.digest;
        count++;
    }
    for (const ListLibItem &ilib : libs) {
        if (!ilib.digest.empty()) {
            v["fingers"][count]["dbid"] = ilib.order;
            v["fingers"][count]["name"] = ilib.abspath;
            v["fingers"][count]["finger"] = ilib.digest;
            count++;
        }
    }

    // process - library graphs
    count = 0;
    for (const ListLibItem &iproc : proc) {
        v["graphs"][count]["exe"] = iproc.order;
	if (iproc.libs.empty()) {
            v["graphs"][count]["dlls"] = json::array();
        } else {
            vector<int> orders;
	    for (const ListLibItem *ilib : iproc.libs) {
                orders.push_back(ilib->order);
            }
            v["graphs"][count]["dlls"] = orders;
        }
	count++;
    }
    return true;
}

bool load_manifest(Property &prop, const std::string &pfname) {
    regex_t regt;
    regmatch_t match[3];
    if (regcomp(&regt, "(\\S+)\\s*=\\s*(\\S+)", REG_EXTENDED)) {
        return false;
    }
    try {
        ifstream ifs(pfname);
	string s;
        while (getline(ifs, s)) {
            if (regexec(&regt, s.c_str(), 3, &match[0], 0) == 0) {
                string key(s.data() + match[1].rm_so, match[1].rm_eo - match[1].rm_so);
                string val(s.data() + match[2].rm_so, match[2].rm_eo - match[2].rm_so);
		prop.insert(pair<string, string>(key, val));
            }
        }
    } catch (void *) {
    }
    regfree(&regt);
    return true;
}

void kill_processes(const json &json_res) {
    if (json_res.empty()) {
        return;
    }
    if (json_res[0] == true) {
        if (json_res[1].find("kill_black_processes") != json_res[1].cend()) {
            kill_black_processes(json_res[1]);
        }
    } else {
        string er(json_res[1].get<string>());
	fprintf(stderr, "server error: %.*s\n", (int)er.length(), er.data());
    }
}

void kill_black_processes(const json &json_black) {
    auto blacks = json_black.find("kill_black_processes");
    if (blacks == json_black.cend()) {
        return;
    }
    for (auto black = blacks->cbegin(); black != blacks->cend(); black++) {
        auto iorder = order_cache.find(black->get<int>());
	if (iorder != order_cache.cend()) {
            ListLibItem *pi = iorder->second;
            kill(pi->pid, SIGKILL);
        }
    }
}

const std::string make_s(const char *p) {
    return std::string(p);
}
