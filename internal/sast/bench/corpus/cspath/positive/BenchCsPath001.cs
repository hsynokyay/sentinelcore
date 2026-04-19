using System.IO;
using Microsoft.AspNetCore.Http;

namespace Bench {
    public class BenchCsPath001 {
        public string Read(HttpRequest request) {
            string filename = request.Query["file"];
            return File.ReadAllText(filename);
        }
    }
}
