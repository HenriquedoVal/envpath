using System;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace BinEnvPath
{
    public static class EnvPath
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

    public class Main : PSCmdlet
    {
        public void Error(string msg)
        {
            WriteError(new ErrorRecord(
                        new ApplicationException(msg),
                        msg,
                        ErrorCategory.InvalidResult,
                        null));
        }

        public bool Prolog()
        {
            bool ret = EnvPath.set_tmp_outputs();
            if (!ret)
                Error("Could not set output buffers");
            return ret;
        }

        public void Epilog()
        {
            if (!EnvPath.reset_tmp_outputs())
                Error("Could not reset output buffers");
        }
    }

    public class TestOutput
    {
        public string Info { get; set; }
        public string Path { get; set; }
    }

    [Cmdlet(VerbsDiagnostic.Test, "EnvPath")]
    [OutputType(typeof(TestOutput))]
    public class TestEnvPath : Main
    {
        protected override void BeginProcessing()
        {
            if (!Prolog()) return;

            bool verbose = this.MyInvocation.BoundParameters.ContainsKey(
                    "Verbose");

            bool ret = EnvPath.diagnose(verbose);
            if (!ret) {
                Error($"Call to `diagnose({verbose})` failed");

            } else {
                string info = EnvPath.get_stderr();
                if (info is null) Error("Could not get dll's stderr");

                string path = EnvPath.get_stdout();
                if (path is null) Error("Could not get dll's stdout");

                WriteObject(new TestOutput { Info = info, Path = path });
            }

            Epilog();
        }
    }

    [Cmdlet(VerbsData.Update, "EnvPath")]
    [OutputType(typeof(void))]
    public class UpdateEnvPath : Main
    {
        protected override void BeginProcessing()
        {
            if (!Prolog()) return;

            bool ret = EnvPath.update();
            if (!ret) Error("Call to `update` failed");

            Epilog();
        }
    }

    [OutputType(typeof(string))]
    public abstract class AddOrRemove : Main
    {
        [Parameter(Mandatory = true, Position = 0)]
        [Alias("T")]
        public EnvPath.Target Target { get; set; }

        [Parameter(Mandatory = true, Position = 1)]
        public string Path { get; set; }

        [Parameter()]
        [Alias("E")]
        public SwitchParameter Exact { get; set; }

        public abstract bool dll_function(
                EnvPath.Target t, string s, bool v, bool e);

        protected override void BeginProcessing()
        {
            if (!Prolog()) return;

            bool exact = Exact.IsPresent;
            bool verbose = this.MyInvocation.BoundParameters.ContainsKey(
                    "Verbose");

            bool ret = dll_function(Target, Path, verbose, exact);
            if (!ret) Error("Error");

            string info = EnvPath.get_stderr();
            if (info is null) Error("Could not get dll's stderr");

            if (info.Length > 0) WriteObject(info);

            Epilog();
        }
    }

    [Cmdlet(VerbsCommon.Add, "EnvPath")]
    public class AddEnvPath : AddOrRemove
    {
        public override bool dll_function(
                EnvPath.Target t, string s, bool v, bool e
        ) => EnvPath.add_path(t, s, v, e);
    }

    [Cmdlet(VerbsCommon.Remove, "EnvPath")]
    public class RemoveEnvPath : AddOrRemove
    {
        public override bool dll_function(
                EnvPath.Target t, string s, bool v, bool e
        ) => EnvPath.remove_path(t, s, v, e);
    }
}
