using System;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace envpath
{
    public static class Envpath
    {
        public enum Target : int {
            User,
            Machine
        };

        // __declspec(dllexport) bool diagnose(bool verbose);
        [DllImport("envpath.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool diagnose(
                [MarshalAs(UnmanagedType.I1)] bool verbose);

        // __declspec(dllexport) bool update(void);
        [DllImport("envpath.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool update();

        // __declspec(dllexport) bool set_tmp_outputs(void);
        [DllImport("envpath.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool set_tmp_outputs();

        // __declspec(dllexport) bool reset_tmp_outputs(void);
        [DllImport("envpath.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool reset_tmp_outputs();

        // __declspec(dllexport) char *get_stdout(void);
        [DllImport("envpath.dll", CharSet = CharSet.Ansi)]
        public static extern string get_stdout();

        // __declspec(dllexport) char *get_stderr(void);
        [DllImport("envpath.dll", CharSet = CharSet.Ansi)]
        public static extern string get_stderr();

        // bool add_path(
        //      Target t, const char *path, bool verbose, bool exact);
        [DllImport("envpath.dll", CharSet = CharSet.Ansi)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool add_path(
                Target target,
                string path,
                [MarshalAs(UnmanagedType.I1)] bool verbose,
                [MarshalAs(UnmanagedType.I1)] bool exact);

        // bool remove_path(
        //      Target t, const char *path, bool verbose, bool exact);
        [DllImport("envpath.dll", CharSet = CharSet.Ansi)]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool remove_path(
                Target target,
                string path,
                [MarshalAs(UnmanagedType.I1)] bool verbose,
                [MarshalAs(UnmanagedType.I1)] bool exact);
    }

    public class Mid : PSCmdlet
    {
        public void Error(string msg)
        {
            WriteError(new ErrorRecord(
                        new ApplicationException(msg),
                        msg,
                        ErrorCategory.InvalidResult,
                        null
            ));
        }
    }

    [Cmdlet(VerbsData.Update, "EnvPath")]
    [OutputType(typeof(void))]
    public class UpdateEnvPath : Mid
    {
        protected override void BeginProcessing()
        {
            bool ret = Envpath.set_tmp_outputs();
            if (!ret) {
                Error("Could not set output buffers");
                return;
            }

            ret = Envpath.update();
            if (!ret) Error("Call to `update` failed");

            ret = Envpath.reset_tmp_outputs();
            if (!ret) Error("Could not reset output buffers");
        }
    }

    public class Output
    {
        public string Info { get; set; }
        public string Path { get; set; }
    }

    [Cmdlet(VerbsDiagnostic.Test, "EnvPath")]
    [OutputType(typeof(Output))]
    public class TestEnvPath : Mid
    {
        protected override void BeginProcessing()
        {
            bool verbose = this.MyInvocation.BoundParameters.ContainsKey(
                    "Verbose");

            bool ret = Envpath.set_tmp_outputs();
            if (!ret) {
                Error("Could not set output buffers");
                return;
            }

            ret = Envpath.diagnose(verbose);
            if (!ret) {
                Error($"Call to `diagnose({verbose})` failed");

            } else {
                string info = Envpath.get_stderr();
                if (info is null) Error("Could not get dll's stderr");

                string path = Envpath.get_stdout();
                if (path is null) Error("Could not get dll's stdout");

                WriteObject(new Output { Info = info, Path = path });
            }

            ret = Envpath.reset_tmp_outputs();
            if (!ret) Error("Could not reset output buffers");
        }
    }

    [OutputType(typeof(string))]
    public abstract class AddOrRemove : Mid
    {
        [Parameter(Mandatory = true)]
        [Alias("T")]
        public Envpath.Target Target { get; set; }

        [Parameter(Mandatory = true, Position = 0)]
        public string Path { get; set; }

        [Parameter()]
        [Alias("E")]
        public SwitchParameter Exact { get; set; }

        public abstract bool dll_function(
                Envpath.Target t, string s, bool v, bool e);

        protected override void BeginProcessing()
        {
            bool verbose = this.MyInvocation.BoundParameters.ContainsKey(
                    "Verbose");
            bool ret = Envpath.set_tmp_outputs();
            if (!ret) {
                Error("Could not set output buffers");
                return;
            }

            bool exact = Exact.IsPresent;
            ret = dll_function(Target, Path, verbose, exact);
            if (!ret) Error("Error");

            string info = Envpath.get_stderr();
            if (info is null) Error("Could not get dll's stderr");

            WriteObject(info);

            ret = Envpath.reset_tmp_outputs();
            if (!ret) Error("Could not reset output buffers");
        }
    }

    [Cmdlet(VerbsCommon.Add, "EnvPath")]
    public class AddEnvPath : AddOrRemove
    {
        public override bool dll_function(
                Envpath.Target t, string s, bool v, bool e
        ) => Envpath.add_path(t, s, v, e);
    }

    [Cmdlet(VerbsCommon.Remove, "EnvPath")]
    public class RemoveEnvPath : AddOrRemove
    {
        public override bool dll_function(
                Envpath.Target t, string s, bool v, bool e
        ) => Envpath.remove_path(t, s, v, e);
    }
}
