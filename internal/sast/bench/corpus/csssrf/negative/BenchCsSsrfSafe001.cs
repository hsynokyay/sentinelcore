using System.Net.Http;

namespace Bench {
    public class BenchCsSsrfSafe001 {
        public void Fetch(HttpClient client) {
            var res = client.GetAsync("https://api.example.com/data");
        }
    }
}
