package ofl.sandbox.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

import lombok.Getter;

@Slf4j
@Service
public class JwtService {
    @Getter
    private final SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_MS = 1000 * 60 * 15; // 15 min

    public String generateToken(String username, List<String> entitlements) {
        return Jwts.builder()
                .setSubject(username)
                .claim("entitlements", entitlements)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .signWith(key)
                .compact();
    }

    public Jws<Claims> parseToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
    }

    public String getUsername(String token) {
        return parseToken(token).getBody().getSubject();
    }

    public List<String> getEntitlements(String token) {
        // FIXME: the unchecked casting from List to List<String> - use ObjectMapper TypeReference
        return parseToken(token).getBody().get("entitlements", List.class);
    }

    public boolean isTokenValid(String token) {
        try {
            List<String> entitlements = getEntitlements(token);

            log.info("Got {} entitlements for {}", entitlements,
                    getUsername(token));
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

}
