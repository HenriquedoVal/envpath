#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <io.h>

#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#pragma comment(lib, "Advapi32")  // Registry

#define DYNARR_IMPLEMENTATION
#define DYNARR_SCOPE_STATIC
#include "dynarr.h"

#include "envpath.h"


#define ENV_STDOUT 0
#define ENV_STDERR 1

static FILE *outputs[2] = {0};


typedef unsigned char u8;

static char *get_registry_envpath(bool system)
{
    HKEY query_key = HKEY_CURRENT_USER;
    if (system) query_key = HKEY_LOCAL_MACHINE;

    char *subkey = "Environment";
    if (system) subkey = "SYSTEM\\CurrentControlSet\\Control\\"
                         "Session Manager\\Environment";

    HKEY key = NULL;
    LSTATUS st = RegOpenKeyExA(query_key, subkey, 0, KEY_READ, &key);
    if (st != ERROR_SUCCESS) return NULL;

    // Using RegGetValueA should do the expanding but I could not use it.
    // Following docs leads to error
    DWORD required;
    st = RegQueryValueExA(key, "Path", NULL, NULL, NULL, &required);
    if (st != ERROR_SUCCESS) return NULL;

    DWORD type;
    char *unexpanded = malloc(required);
    st = RegQueryValueExA(key, "Path", NULL, &type, (u8 *)unexpanded, &required);
    if (st != ERROR_SUCCESS) return NULL;

    st = RegCloseKey(key);
    if (st != ERROR_SUCCESS) return NULL;

    switch (type) {
        case REG_SZ:
            return unexpanded;

        case REG_EXPAND_SZ:
            required = ExpandEnvironmentStringsA(unexpanded, NULL, 0);
            if (!required) return NULL;

            char *expanded = malloc(required);
            required = ExpandEnvironmentStringsA(
                unexpanded, expanded, required);
            if (!required) return NULL;

            free(unexpanded);
            return expanded;

        default:
            return NULL;
    }
}


static bool set_registry_envpath(
    bool system, const char *path, bool has_envvar)
{
    HKEY query_key = HKEY_CURRENT_USER;
    if (system) query_key = HKEY_LOCAL_MACHINE;

    char *subkey = "Environment";
    if (system) subkey = "SYSTEM\\CurrentControlSet\\Control\\"
                         "Session Manager\\Environment";

    HKEY key = NULL;
    LSTATUS st = RegOpenKeyExA(query_key, subkey, 0, KEY_SET_VALUE, &key);
    if (st != ERROR_SUCCESS) return false;

    size_t size = strlen(path) + 1;
    if (size > MAXDWORD) return false;

    DWORD type = has_envvar ? REG_EXPAND_SZ : REG_SZ;
    st = RegSetKeyValueA(key, NULL, "Path", type, path, (DWORD)size);
    if (st != ERROR_SUCCESS) return false;

    st = RegCloseKey(key);
    if (st != ERROR_SUCCESS) return false;

    return true;
}


static DynArr to_dynarr(char *path_like, bool verbose, const char *header)
{
    DynArr da = dynarr_init(sizeof(char *));

    char *delim = ";";
    char *tok, *ntok;
    tok = strtok_s(path_like, delim, &ntok);

    if (verbose) fprintf(outputs[ENV_STDERR], "%s\n", header);

    do {
        char **saved = dynarr_append(&da, &tok);
        assert(*saved == tok);

        if (verbose) fprintf(outputs[ENV_STDERR], "%s\n", tok);

    } while ((tok = strtok_s(NULL, delim, &ntok)));

    if (verbose) fprintf(outputs[ENV_STDERR], "\n");

    return da;
}


static bool set_normalized_path(char *dest, int dest_size, const char *path)
{
    HANDLE handle = CreateFile(
        path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );
    if (INVALID_HANDLE_VALUE == handle) return false;

    if (!GetFinalPathNameByHandleA(handle, dest, dest_size, FILE_NAME_NORMALIZED)) {
        CloseHandle(handle);
        return false;
    }

    CloseHandle(handle);

    return true;
}


// Append to `idxs` every index of an element of `target` that
// is already present in `base`
static void append_target_equal_idxs(
    DynArr *idxs,
    DynArr *base,
    DynArr *target)
{
    assert(idxs->count == 0);

    for (int i = 0; i < (int)target->count; ++i) {
        char **target_str = dynarr_at(target, i); assert(target_str);

        for (int j = 0; j < (int)base->count; ++j) {
            char **base_str = dynarr_at(base, j); assert(base_str);

            if (_stricmp(*base_str, *target_str) == 0) {
                int *ret = dynarr_set_append(idxs, &i);
                assert(ret != NULL);
                break;
            }
        }
    }
}


static void remove_idxs(DynArr *idxs, DynArr *target)
{
    for (int i = (int)idxs->count - 1; i >= 0; --i) {
        int *idx = dynarr_at(idxs, i);
        assert(idx != NULL);
        bool ret = dynarr_remove(target, *idx);
        assert(ret);
    }

    idxs->count = 0;
}


static DynArr get_union(DynArr *sys, DynArr *usr, DynArr *inh)
{
    DynArr *arr[3] = {sys, usr, inh};
    DynArr ret = dynarr_init_ex(
        sizeof(char *), sys->count + usr->count + inh->count);

    for (int i = 0; i < _countof(arr); ++i) {
        DynArr *target = arr[i];
        for (unsigned j = 0; j < target->count; ++j) {
            char **s = dynarr_at(target, j);
            char **test = dynarr_append(&ret, s);
            assert(*test == *s);
        }
    }

    return ret;
}


static void warn_maybe_empty_paths(DynArr *target, char *origin, DynArr *ext, char *pathext)
{
    bool did_print_header = false;
    for (int i = 0; i < (int)target->count; ++i) {
        char **path = dynarr_at(target, i);
        bool found_something = false;

        for (unsigned j = 0; j < ext->count; ++j) {
            char **extension = dynarr_at(ext, j);
            char buf[MAX_PATH];
            sprintf_s(buf, MAX_PATH, "%s\\*%s", *path, *extension);

            WIN32_FIND_DATAA ffd;
            HANDLE find = FindFirstFileA(buf, &ffd);
            if (find == INVALID_HANDLE_VALUE) continue;
            found_something = true;
            FindClose(find);
            break;
        }

        if (found_something) continue;

        if (!did_print_header) {
            did_print_header = true;
            fprintf(outputs[ENV_STDERR], "%s PATH entries that maybe don't"
                   " have relevant files inside\n", origin);
        }

        fprintf(outputs[ENV_STDERR], "%s\n", *path);
    }

    if (did_print_header) fprintf(outputs[ENV_STDERR], "\n");
}


static void sanitize_dups_in_itself(DynArr *idxs, DynArr *sys, DynArr *usr, bool print_info)
{
    DynArr *arr[] = {sys, usr};
    char msgs[][7] = {"System", "User"};

    for (int i = 0; i < _countof(arr); ++i) {
        DynArr *target = arr[i];
        char *msg = msgs[i];

        for (int j = 0; j < (int)target->count - 1; ++j) {
            for (int k = j + 1; k < (int)target->count; k++) {
                char **a = dynarr_at(target, j);
                char **b = dynarr_at(target, k);
                if (_stricmp(*a, *b) == 0) {
                    if (print_info)
                        fprintf(outputs[ENV_STDERR], "Duplicated entry in %s Registry: %s\n", msg, *a);

                    int *ret = dynarr_set_append(idxs, &i);
                    assert(*ret == i);
                    break;
                }
            }
        }

        remove_idxs(idxs, target);
    }
}


static bool sanitize_normalized_paths(
    DynArr *idxs,
    DynArr *target,
    DynArr *norm,
    bool print_info,
    char *origin)
{
    bool ret = false;
    bool did_print_header = false;

    char buf[MAX_PATH];
    for (unsigned i = 0; i < target->count; ++i) {
        memset(buf, 0, MAX_PATH);
        char **s = dynarr_at(target, i);

        // let it append zeroes on error
        set_normalized_path(buf, MAX_PATH, *s);
        char *ret = dynarr_append(norm, buf);
        assert(memcmp(ret, buf, MAX_PATH) == 0);
    }
    assert(norm->count == target->count);

    for (int i = 0; i < (int)norm->count - 1; ++i) {
        char *a = dynarr_at(norm, i);

        for (unsigned j = i + 1; j < norm->count; ++j) {
            char *b = dynarr_at(norm, j);

            if (strcmp(a, b)) continue;

            ret = true;
            int *ret = dynarr_set_append(idxs, &i);
            assert(ret != NULL && *ret == i);

            if (!print_info) continue;

            if (!did_print_header) {
                did_print_header = true;
                fprintf(outputs[ENV_STDERR],
                        "%s PATH duplicates after normalization:\n",
                        origin);
            }

            char **sa = dynarr_at(target, i);
            char **sb = dynarr_at(target, j);
            fprintf(
                outputs[ENV_STDERR],
                "a -> %s and ...\nb -> %s resolves to the same path\n",
                *sa, *sb);
        }
    }
    if (did_print_header) fprintf(outputs[ENV_STDERR], "\n");

    remove_idxs(idxs, target);

    norm->count = 0;
    return ret;
}


static bool sanitize_invalid_path(
    DynArr *idxs,
    DynArr *target,
    bool print_info,
    char *origin)
{
    bool ret = false;
    bool did_print_header = false;

    for (int i = 0; i < (int)target->count; ++i) {
        char **path = dynarr_at(target, i);
        DWORD attr = GetFileAttributesA(*path);
        if (attr != INVALID_FILE_ATTRIBUTES &&
            attr & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        ret = true;
        int *ret = dynarr_set_append(idxs, &i);
        assert(ret != NULL);

        if (!print_info) continue;
        if (!did_print_header) {
            did_print_header = true;
            fprintf(
                outputs[ENV_STDERR],
                "%s PATH paths that doesn't exist or aren't directories:\n",
                origin);
        }
        fprintf(outputs[ENV_STDERR], "%s\n", *path);

    }
    if (did_print_header) fprintf(outputs[ENV_STDERR], "\n");

    remove_idxs(idxs, target);
    return ret;
}


static DynArr sanitize(
    DynArr *sys,
    DynArr *usr,
    DynArr *inh,
    bool print_info)
{
    DynArr idxs = dynarr_init(sizeof(int));
    DynArr norm = dynarr_init(MAX_PATH);

    char *pathext = NULL;
    size_t size;
    _dupenv_s(&pathext, &size, "PATHEXT");

    DynArr ext = to_dynarr(pathext, false, NULL);
    char extra[2][5] = { ".dll", ".ps1" };
    for (int i = 0; i < 2; ++i) {
        char *test = extra[i];
        char **ret = dynarr_append(&ext, &test);
        assert(*ret == test);
    }

    sanitize_dups_in_itself(&idxs, sys, usr, print_info);

    sanitize_invalid_path(&idxs, sys, print_info, "SYSTEM");
    sanitize_normalized_paths(&idxs, sys, &norm, print_info, "SYSTEM");
    if (print_info) warn_maybe_empty_paths(sys, "SYSTEM", &ext, pathext);

    // remove every entry from user that are in sys
    append_target_equal_idxs(&idxs, sys, usr);

    if (print_info && idxs.count)
        fprintf(outputs[ENV_STDERR],
                "These are the entries on User PATH that duplicates System"
                " PATH.\nConsider removing those form User:\n");

    for (int i = (int)idxs.count - 1; i >= 0; --i) {
        int *dup_idx = dynarr_at(&idxs, i);
        if (print_info) {
            char **s = dynarr_at(usr, *dup_idx);
            fprintf(outputs[ENV_STDERR], "%s\n", *s);
        }
        bool ret = dynarr_remove(usr, *dup_idx);
        assert(ret);
    }
    if (print_info && idxs.count) fprintf(outputs[ENV_STDERR], "\n");
    idxs.count = 0;

    sanitize_invalid_path(&idxs, usr, print_info, "USER");
    sanitize_normalized_paths(&idxs, usr, &norm, print_info, "USER");
    if (print_info) warn_maybe_empty_paths(usr, "USER", &ext, pathext);

    // remove every entry in inh that are in sys or usr
    append_target_equal_idxs(&idxs, sys, inh);
    remove_idxs(&idxs, inh);
    append_target_equal_idxs(&idxs, usr, inh);
    remove_idxs(&idxs, inh);

    sanitize_invalid_path(&idxs, inh, print_info, "INHERITED");
    sanitize_normalized_paths(&idxs, inh, &norm, print_info, "INHERITED");
    if (print_info) warn_maybe_empty_paths(inh, "INHERITED", &ext, pathext);

    DynArr u = get_union(sys, usr, inh);
    sanitize_normalized_paths(&idxs, &u, &norm, print_info, "UNIFIED");

    dynarr_free(&norm);
    dynarr_free(&idxs);
    dynarr_free(&ext);
    free(pathext);

    return u;
}


static char *da_to_envvar(DynArr *target, bool print_info, char *msg)
{
    size_t size = 0;
    if (print_info) fprintf(outputs[ENV_STDERR], "%s\n", msg);

    for (unsigned i = 0; i < target->count; ++i) {
        char **s = dynarr_at(target, i);
        assert(s != NULL && *s != NULL);
        size += strlen(*s);

        if (i != target->count - 1) size += strlen(";");
        if (print_info) fprintf(outputs[ENV_STDERR], "%s\n", *s);
    }
    if (print_info) fprintf(outputs[ENV_STDERR], "\n");

    size++;  // null terminate
    char *dest = malloc(size);
    assert(dest != NULL);

    char *ptr = dest;
    int written = 0;
    for (unsigned i = 0; i < target->count; i++) {
        char **s = dynarr_at(target, i);
        assert(s != NULL && *s != NULL);

        char *mask = "%s;";
        if (i == target->count - 1) mask = "%s";

        int it_written = sprintf_s(ptr, size - written, mask, *s);
        assert(it_written > 0 && it_written < (int)size - written);

        ptr += it_written;
        written += it_written;
    }
    assert(written == size - 1);

    return dest;
}


static char *get_sanitized_envpath(bool diagnose, bool verbose)
{
    bool is_system = true;
    char *sys_path = get_registry_envpath(is_system);
    if (sys_path == NULL) return NULL;

    is_system = false;
    char *usr_path = get_registry_envpath(is_system);
    if (usr_path == NULL) return NULL;
    
    char *inh_path;
    size_t path_size;
    errno_t err = _dupenv_s(&inh_path, &path_size, "PATH");
    if (err) return NULL;

    DynArr sys_da = to_dynarr(sys_path, verbose, "System PATH from Registry");
    DynArr usr_da = to_dynarr(usr_path, verbose, "User PATH from Registry");
    DynArr inh_da = to_dynarr(inh_path, verbose, "Inherited PATH");

    DynArr final = sanitize(&sys_da, &usr_da, &inh_da, diagnose);
    char *envpath = da_to_envvar(&final, diagnose, "Sanitized final path:");

    dynarr_free(&final);
    dynarr_free(&sys_da);
    dynarr_free(&usr_da);
    dynarr_free(&inh_da);

    free(sys_path);
    free(usr_path);
    free(inh_path);

    return envpath;
}


static bool da_unexpand(DynArr *da)
{
    bool unexpanded = false;

    char *var_name[] = {
        "LocalAppData",
        "AppData",
        "UserProfile",
        "SystemRoot",
        "ProgramFiles",
        "Windir",
    };

    DynArr vars = dynarr_init_ex(sizeof(char *), _countof(var_name));

    for (int i = 0; i < _countof(var_name); ++i) {
        char *dest = NULL;
        size_t size;
        _dupenv_s(&dest, &size, var_name[i]);
        char **s = dynarr_append(&vars, &dest);
        assert(s && *s == dest);
    }

    for (unsigned i = 0; i < vars.count; ++i) {
        char **var = dynarr_at(&vars, i);
        if (!var || !*var) continue;

        for (unsigned j = 0; j < da->count; ++j) {
            char **s = dynarr_at(da, j);
            assert(s && *s);
            char *found = strstr(*s, *var);
            if (!found || found != *s) continue;

            unexpanded = true;
            size_t size = strlen(*s) + 1;
            size_t len = strlen(*var);
            int written = sprintf_s(*s, size,
                                    "%%%s%%%s",
                                    var_name[i], *s + len);
            assert(written > 0 && (size_t)written < size);
        }
    }

    for (unsigned i = 0; i < vars.count; ++i) {
        char **s = dynarr_at(&vars, i);
        free(*s);
    }
    dynarr_free(&vars);

    return unexpanded;
}


static char *get_output(int i)
{
    fflush(outputs[i]);

    int pos = ftell(outputs[i]);

    char *ret = malloc(pos + 1);
    if (ret == NULL) return NULL;

    fseek(outputs[i], 0, 0);
    size_t r = fread(ret, 1, pos, outputs[i]);
    ret[r] = 0;

    // The file will be closed after the read

    // _chsize_s(_fileno(outputs[i]), 0);

    return ret;
}


void EXPORT set_std_outputs(void)
{
    outputs[ENV_STDOUT] = stdout;
    outputs[ENV_STDERR] = stderr;
}


bool EXPORT set_tmp_outputs(void)
{
    const char *targets[] = { "stdout", "stderr" };

    for (int i = 0; i < 2; ++i) {
        char tmp[MAX_PATH];
        size_t required;
        errno_t err = getenv_s(&required, tmp, MAX_PATH, "TMP");
        if (err || required > MAX_PATH) return false;

        char file_path[MAX_PATH];
        int w = sprintf_s(file_path, MAX_PATH, "%s\\envpath_dll_%s.temp", tmp, targets[i]);
        if (w <= 0 || w > MAX_PATH) return false;

        outputs[i] = _fsopen(file_path, "w+TD", _SH_DENYRW);
        if (outputs[i] == NULL) return false;
    }

    return true;
}


bool EXPORT reset_tmp_outputs(void)
{
    if (outputs[ENV_STDOUT] == stdout) return false;
    if (outputs[ENV_STDERR] == stderr) return false;

    int err;
    err = fclose(outputs[ENV_STDOUT]);
    if (err) return false;
    err = fclose(outputs[ENV_STDERR]);
    if (err) return false;

    return true;
}


char EXPORT *get_stdout(void)
{
    return get_output(ENV_STDOUT);
}


char EXPORT *get_stderr(void)
{
    return get_output(ENV_STDERR);
}


bool EXPORT update(void)
{
    bool diagnose = false;
    bool verbose  = false;
    char *envpath = get_sanitized_envpath(diagnose, verbose);
    if (envpath == NULL) return false;

    errno_t err = _putenv_s("PATH", envpath);
    free(envpath);

    return err == 0;
}


bool EXPORT diagnose(bool verbose)
{
    bool diagnose = true;
    char *envpath = get_sanitized_envpath(diagnose, verbose);
    if (envpath == NULL) return false;

    fprintf(outputs[ENV_STDOUT], "%s", envpath);

    free(envpath);
    return true;
}


bool EXPORT add_path(
    Target t, const char *_path, bool verbose, bool exact)
{
/// "copy_and_paste" from `remove_path`
    if (_path == NULL) return false;
    char *path = _strdup(_path);
    if (path == NULL) return false;

    bool ret = false;

    DynArr sup;
    char _buf[MAX_PATH];
    if (exact) {
        sup = dynarr_init_ex(sizeof(char *), 1);
        dynarr_append(&sup, &path);
    } else if (set_normalized_path(_buf, MAX_PATH, path)) {
        char *buf = _buf + 4;
        sup = dynarr_init_ex(sizeof(char *), 1);
        char **test = dynarr_append(&sup, &buf);
        assert(test && *test);
        assert(*test == buf);

        if (verbose)
            fprintf(outputs[ENV_STDERR], "Adding path:\n%s\n\n", buf);
    } else {
        sup = to_dynarr(path, verbose, "Adding paths:"); 
    }

    char *target_path = get_registry_envpath(t);
    if (target_path == NULL) goto cleanup1;

    char *headers[] = {
        "User Path from Registry",
        "Machine Path from Registry",
    };
    DynArr tar = to_dynarr(target_path, verbose, headers[t]);

    DynArr idxs = dynarr_init(sizeof(int));
///

    DynArr dup_tar = dynarr_dup(tar);
    append_target_equal_idxs(&idxs, &dup_tar, &sup);
    if (idxs.count) {
        for (unsigned i = 0; i < idxs.count; ++i) {
            int *idx = dynarr_at(&idxs, i);
            char **p = dynarr_at(&sup, *idx);
            fprintf(outputs[ENV_STDERR],
                    "%s already in %s\n",
                    *p, headers[t]);
        }
    }
    remove_idxs(&idxs, &sup);
    if (!sup.count) goto cleanup2;

    bool always_print = true;
    sanitize_invalid_path(&idxs, &sup, always_print, "Supplied");
    if (!sup.count) goto cleanup2;

    DynArr norm = dynarr_init(MAX_PATH);

    // cleanup target so we only report what was supplied
    sanitize_normalized_paths(&idxs, &dup_tar, &norm, false, NULL);

    for (unsigned i = 0; i < sup.count; ++i) {
        char **s = dynarr_at(&sup, i);
        char **ret = dynarr_append(&dup_tar, s);
        assert(*s == *ret);
    }

    // dup_tar was sanitized before, so the only thing that makes this thing
    // fails here, are those that are in sup
    if (sanitize_normalized_paths(&idxs, &dup_tar, &norm, always_print, "Supplied"))
        goto cleanup3;

/// small copy_and_paste
    char *pathext = NULL;
    size_t size;
    _dupenv_s(&pathext, &size, "PATHEXT");

    DynArr ext = to_dynarr(pathext, false, NULL);
    char extra[2][5] = { ".dll", ".ps1" };
    for (int i = 0; i < 2; ++i) {
        char *test = extra[i];
        char **ret = dynarr_append(&ext, &test);
        assert(*ret == test);
    }
/// 

    warn_maybe_empty_paths(&sup, "Supplied", &ext, pathext);

    // sup is ok, append to tar and write it back
    for (unsigned i = 0; i < sup.count; ++i) {
        char **s = dynarr_at(&sup, i);
        char **t = dynarr_append(&tar, s);
        assert(s && *s && t && *t);
        assert(*s == *t);
    }

    bool has_envvar = da_unexpand(&tar);
    char *envpath = da_to_envvar(&tar, false, NULL);

    ret = set_registry_envpath(t, envpath, has_envvar);
    if (!ret)
        fprintf(outputs[ENV_STDERR], "Could not set registry value\n");

    free(envpath);
    dynarr_free(&ext);
    free(pathext);
cleanup3:
    dynarr_free(&norm);
cleanup2:
    dynarr_free(&dup_tar);
    dynarr_free(&idxs);
    dynarr_free(&tar);
    free(target_path);
cleanup1:
    dynarr_free(&sup);
    free(path);

    return ret;
}


bool EXPORT remove_path(
    Target t, const char *_path, bool verbose, bool exact)
{
    if (_path == NULL) return false;
    char *path = _strdup(_path);
    if (path == NULL) return false;

    bool ret = false;

    DynArr sup;
    char _buf[MAX_PATH];
    if (exact) {
        sup = dynarr_init_ex(sizeof(char *), 1);
        dynarr_append(&sup, &path);
    } else if (set_normalized_path(_buf, MAX_PATH, path)) {
        char *buf = _buf + 4;
        sup = dynarr_init_ex(sizeof(char *), 1);
        char **test = dynarr_append(&sup, &buf);
        assert(test && *test);
        assert(*test == buf);

        if (verbose)
            fprintf(outputs[ENV_STDERR], "Removing path:\n%s\n\n", buf);
    } else {
        sup = to_dynarr(path, verbose, "Removing paths:"); 
    }

    char *target_path = get_registry_envpath(t);
    if (target_path == NULL) return false;

    char *headers[] = {
        "User Path from Registry",
        "Machine Path from Registry",
    };
    DynArr tar = to_dynarr(target_path, verbose, headers[t]);

    DynArr not_there = dynarr_init(sizeof(int));
    DynArr idxs = dynarr_init(sizeof(int));
    append_target_equal_idxs(&idxs, &tar, &sup);
    for (unsigned i = 0; i < sup.count; ++i) {
        bool there = false;
        for (unsigned j = 0; j < idxs.count; ++j) {
            int *idx = dynarr_at(&idxs, j);
            if (*idx == i) {
                there = true;
                break;
            }
        }
        if (there) continue;

        char **s = dynarr_at(&sup, i);
        fprintf(outputs[ENV_STDERR], "%s is not in %s\n", *s, headers[t]);
        dynarr_append(&not_there, &i);
    }

    remove_idxs(&not_there, &sup);
    if (!sup.count) goto cleanup1;

    idxs.count = 0;
    append_target_equal_idxs(&idxs, &sup, &tar);
    remove_idxs(&idxs, &tar);

    bool has_envvar = da_unexpand(&tar);
    char *envpath = da_to_envvar(&tar, false, NULL);

    ret = set_registry_envpath(t, envpath, has_envvar);
    if (!ret)
        fprintf(outputs[ENV_STDERR], "Could not set registry value\n");

    free(envpath);
cleanup1:
    dynarr_free(&not_there);
    dynarr_free(&idxs);
    dynarr_free(&sup);
    dynarr_free(&tar);
    free(target_path);
    free(path);

    return ret;
}
