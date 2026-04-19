using System.IO;

namespace Bench {
    public class BenchCsPathSafe001 {
        public string Read() {
            return File.ReadAllText("/var/data/config.json");
        }
    }
}
