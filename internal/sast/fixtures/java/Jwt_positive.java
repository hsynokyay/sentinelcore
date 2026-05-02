import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtPositive {
    private static final String JWT_SECRET = "supersecretpassword12345"; // SC-JAVA-JWT-003

    public Object decodeUnsigned(String token) {
        return Jwts.parser().parseClaimsJwt(token); // SC-JAVA-JWT-001
    }

    public Object decodeAllowsNone(String token) {
        return Jwts.parser().setSigningKey(JWT_SECRET).parse(token, SignatureAlgorithm.NONE); // SC-JAVA-JWT-002
    }
}
