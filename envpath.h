typedef enum {
    USER,
    MACHINE
} Target;

#ifdef DLL_BUILD
#   define EXPORT __declspec(dllexport)
#else
#   define EXPORT
#endif

bool EXPORT diagnose(bool verbose);
bool EXPORT update(void);
void EXPORT set_std_outputs(void);
bool EXPORT set_tmp_outputs(void);
bool EXPORT reset_tmp_outputs(void);
char EXPORT *get_stdout(void);
char EXPORT *get_stderr(void);
bool EXPORT add_path(Target t, const char *path, bool verbose, bool exact);
bool EXPORT remove_path(Target t, const char *path, bool verbose, bool exact);
