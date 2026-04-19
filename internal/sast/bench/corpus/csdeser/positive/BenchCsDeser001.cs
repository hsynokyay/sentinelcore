using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace Bench {
    public class BenchCsDeser001 {
        public object Load(Stream stream) {
            var fmt = new BinaryFormatter();
            return fmt.Deserialize(stream);
        }
    }
}
