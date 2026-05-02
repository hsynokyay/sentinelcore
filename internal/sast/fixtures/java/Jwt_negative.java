import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;

public class JwtNegative {
    private final String secret = System.getenv("JWT_SECRET");

    public Claims verify(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }
}
