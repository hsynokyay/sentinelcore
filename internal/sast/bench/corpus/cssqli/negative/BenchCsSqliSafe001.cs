using System.Data.SqlClient;
using Microsoft.AspNetCore.Http;

namespace Bench {
    public class BenchCsSqliSafe001 {
        public void Get(HttpRequest request, SqlConnection conn) {
            string id = request.Query["id"];
            var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
            cmd.Parameters.AddWithValue("@id", id);
            cmd.ExecuteReader();
        }
    }
}
