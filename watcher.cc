#include "algorithms.h"

using namespace std;
using json = nlohmann::json;

int run(const string &propfilename) {
    string property_filename("/etc/proc_watcher/proc_watcher.conf");
    if (!propfilename.empty()) {
        property_filename = propfilename;
    }

    // load properties
    if (!load_manifest(properties, property_filename)) {
        return 1;
    }

    // ldconfig -p
    if (!load_ldconfig(list_lib, path_cache)) {
        return 1;
    }

    // create proc list
    if (!get_proclist(list_proc, path_cache)) {
        return 1;
    }

    // create process -- library graph
    if (!create_libs(list_proc, list_lib, path_cache)) {
        return 1;
    }

    // numbering for proc, libs
    auto count = numbering(list_proc, 1);
    numbering(list_lib, count);

    // structure to json
    json v;
    if (!create_json(v, list_proc, list_lib)) {
        return 1;
    }

    // upload to the server
    json vres;
    if (!upload_server(properties, v, vres)) {
        return 1;
    }

    // kill command from administrator
    if (!vres.empty()) {
        kill_processes(vres);
    }
    return 0;
}
