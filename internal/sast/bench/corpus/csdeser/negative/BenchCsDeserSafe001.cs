using System.Text.Json;

namespace Bench {
    public class BenchCsDeserSafe001 {
        public User Load(string json) {
            return JsonSerializer.Deserialize<User>(json);
        }
    }

    public class User {
        public string Name { get; set; }
    }
}
