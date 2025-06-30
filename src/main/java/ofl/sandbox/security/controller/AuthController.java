package ofl.sandbox.security.controller;

import lombok.extern.slf4j.Slf4j;
import ofl.sandbox.security.jwt.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtService jwtService;

    private final Map<String, List<String>> entitlementCache = Map.of(
            "alice", List.of("CAN_TRADE", "CAN_VIEW"),
            "bob", List.of("CAN_VIEW"),
            "chris", List.of("CAN_CONNECT_WS")
    );

    public AuthController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestHeader("x-login-id") String loginId) {
        log.info("Received login request for {}", loginId);
        if(!entitlementCache.containsKey(loginId)) {
            log.error("Unauthorised login for {}", loginId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unknown login ID");
        }

        log.error("Login authorised for {} with entitlements: {}", loginId, entitlementCache.get(loginId));
        return ResponseEntity.ok(
                jwtService.generateToken(loginId, entitlementCache.get(loginId))
        );
    }
}
