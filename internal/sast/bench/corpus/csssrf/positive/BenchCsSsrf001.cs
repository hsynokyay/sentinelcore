using System.Net.Http;
using Microsoft.AspNetCore.Http;

namespace Bench {
    public class BenchCsSsrf001 {
        public void Fetch(HttpRequest request, HttpClient client) {
            string url = request.Query["url"];
            var res = client.GetAsync(url);
        }
    }
}
