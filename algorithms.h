#ifndef _ALGORITHNS_H_
#define _ALGORITHMS_H_

/*
 * requried apt packages
 * libcurl4-openssl-dev
 * libkrb5-dev
 * openssl-dev
 */
#include <string>
#include <list>
#include <unordered_map>
#include <algorithm>
#include <openssl/sha.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <curl/curl.h>
#include "json.hpp"

struct ListLibItem {
    std::string abspath;
    std::string digest;
    int order;
    pid_t pid;
    std::list<ListLibItem *> libs;
    ListLibItem() : abspath(), digest(), order(0), pid(0), libs() {}
};

// path & digest storage
typedef std::list<ListLibItem> ListLib;

// relative path to absolute path
typedef std::unordered_map<std::string, ListLibItem *> HashPath;
typedef std::unordered_map<std::string, std::string> Property;
typedef std::unordered_map<int, ListLibItem *> OrderCache;

extern ListLib list_proc;
extern ListLib list_lib;
extern HashPath path_cache;
extern OrderCache order_cache;
extern Property properties;

static bool register_cache(HashPath &cache, ListLib &libs, const std::string &rel, const std::string &abspath) {
    auto p = path_cache.find(rel);
    if (p != path_cache.end()) {
        return false;
    }

    // insert to list_proc or list_lib
    ListLibItem item;
    item.abspath = abspath;
    libs.push_back(item);

    // update a cache
    auto pr = path_cache.insert(std::pair<std::string, ListLibItem *>(rel, &libs.back()));
    return pr.second;
}

// in watcher.cc
int run(const std::string &propfilename);

// in load_ldconfig.cc
bool load_ldconfig(ListLib &libs, HashPath &cache);
bool get_proclist(ListLib &proc, HashPath &cache);

// in graph.cc
bool create_libs(ListLib &proc, ListLib &libs, HashPath &cache);

// in utils.cc
void create_sha256(ListLibItem *plibitem);
int numbering(ListLib &libs, int start);
bool create_json(nlohmann::json &json_code, const ListLib &proc, const ListLib &libs);
bool upload_server(const Property &props, const nlohmann::json &json_code, nlohmann::json &json_resp);
bool load_manifest(Property &props, const std::string &filename);
void kill_processes(const nlohmann::json &json_resp);
void kill_black_processes(const nlohmann::json &json_black);

#endif // algorithms.h

