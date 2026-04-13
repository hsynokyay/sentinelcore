using System.Diagnostics;
using Microsoft.AspNetCore.Http;

namespace Bench {
    public class BenchCsCmd001 {
        public void Run(HttpRequest request) {
            string cmd = request.Query["cmd"];
            Process.Start(cmd);
        }
    }
}
