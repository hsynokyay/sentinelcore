using System.Data.SqlClient;
using Microsoft.AspNetCore.Http;

namespace Bench {
    public class BenchCsSqli002 {
        public void Get(HttpRequest request, SqlConnection conn) {
            string id = request.Query["id"];
            var cmd = new SqlCommand($"SELECT * FROM users WHERE id = {id}", conn);
            cmd.ExecuteReader();
        }
    }
}
