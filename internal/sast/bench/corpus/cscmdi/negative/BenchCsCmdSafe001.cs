using System.Diagnostics;

namespace Bench {
    public class BenchCsCmdSafe001 {
        public void Run() {
            Process.Start("notepad.exe");
        }
    }
}
