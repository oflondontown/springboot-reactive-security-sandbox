package ofl.sandbox.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import lombok.Getter;

@Slf4j
@Service
public class JwtService {
    @Getter
    private final SecretKey userKey;
    @Getter
    private final SecretKey serviceKey;
    private final String serviceId;

    private static final long EXPIRATION_MS = 1000 * 60 * 15; // 15 min

    private final String userAuthSecretKey;

    public JwtService(
            @Value("${user-auth.secret.key}") String userAuthSecretKey,
            @Value("${service-auth.secret.key}") String serviceAuthSecretKey,
            @Value("${service.id}") String serviceId) {
        this.userAuthSecretKey = userAuthSecretKey;
//        this.userKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(userAuthSecretKey));
//        this.serviceKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(serviceAuthSecretKey));
        this.userKey = Keys.hmacShaKeyFor(userAuthSecretKey.getBytes(StandardCharsets.UTF_8));
        this.serviceKey = Keys.hmacShaKeyFor(serviceAuthSecretKey.getBytes(StandardCharsets.UTF_8));
        this.serviceId = serviceId;
    }

//    public SecretKey getUserSecret() {
//        return Keys.hmacShaKeyFor(Base64.getDecoder().decode(userAuthSecretKey));
//    }

    public String issueUserToken(String username, List<String> entitlements) {
        return Jwts.builder()
                .setSubject(username)
                .claim("entitlements", entitlements)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .signWith(userKey, SignatureAlgorithm.HS384)
                .compact();
    }


    /**
     * generate a system Jwt and include the userId
     * @param username
     * @return jwt
     */
    public String issueServiceToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", serviceId)
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plusSeconds(300)))
                .signWith(serviceKey, SignatureAlgorithm.HS384)
                .compact();
    }

    public String getServiceTokenSubject(String serviceAuthToken) {
        return parseServiceToken(serviceAuthToken).getBody().getSubject();
    }

    public String getUserTokenSubject(String userAuthToken) {
        return parseUserToken(userAuthToken).getBody().getSubject();
    }
//
//    public List<String> getUserEntitlements(String token) {
//        // FIXME: the unchecked casting from List to List<String> - use ObjectMapper TypeReference
//        return parseUserToken(token).getBody().get("entitlements", List.class);
//    }

    public boolean isValidServiceToken(String serviceToken, String userToken, String role) {
        Jws<Claims> serviceClaims = parseServiceToken(serviceToken);
        String userId = getUserTokenSubject(userToken);
        return serviceClaims.getBody().get("role", String.class).equals(role)
                && serviceClaims.getBody().getSubject().equals(userId);
    }

    public boolean isValidServiceToken(String serviceToken, String role) {
        Jws<Claims> claims = parseServiceToken(serviceToken);
        return claims.getBody().get("role", String.class).equals(role);
    }

    protected Jws<Claims> parseServiceToken(String token) {
        log.info("Parsing serviceToken: '{}'", token);
        return Jwts.parserBuilder().setSigningKey(serviceKey).build().parseClaimsJws(token.trim());
    }

    protected Jws<Claims> parseUserToken(String token) {
        log.info("Parsing userToken: '{}'", token);
        return Jwts.parserBuilder().setSigningKey(userKey).build().parseClaimsJws(token.trim());
    }


}
