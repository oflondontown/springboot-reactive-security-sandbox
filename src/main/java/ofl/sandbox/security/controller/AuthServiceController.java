package ofl.sandbox.security.controller;

import lombok.extern.slf4j.Slf4j;
import ofl.sandbox.security.jwt.JwtService;
import ofl.sandbox.security.service.UserEntitlementsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.List;

@RestController
@RequestMapping("/api")
@Profile("auth")
@Slf4j
public class AuthServiceController {
    private static final String SERVICE_AUTH_HEADER = "x-service-auth";
    private final JwtService jwtService;
    private final UserEntitlementsService userEntitlementsService;

    public AuthServiceController(@Autowired UserEntitlementsService userEntitlementsService,
                                 @Autowired JwtService jwtService) {
        this.userEntitlementsService = userEntitlementsService;
        this.jwtService = jwtService;
    }

    @PostMapping("/token")
    // cannot use @PreAuthorize here as the token is not a userToken, but a serviceToken
    // and the ReactiveJwtDecoder is expecting by default a userToken in the Authorization Header
    public Mono<ResponseEntity<String>> issue(@RequestHeader(value = SERVICE_AUTH_HEADER, required = false) String authHeader) {
        log.info("Received token issue request: {}", authHeader);
        return Mono.fromCallable(() -> {
            String serviceAuthToken = authHeader != null ? authHeader.replace("Bearer ", "") : "";

            if(!jwtService.isValidServiceToken(serviceAuthToken, "WebService")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid service token");
            }

            String userId = jwtService.getServiceTokenSubject(serviceAuthToken);

            List<String> entitlements = userEntitlementsService.getEntitlements(userId);
            if(entitlements == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unknown login ID");
            }

            String userJwt = jwtService.issueUserToken(userId, entitlements);
            return ResponseEntity.ok(userJwt);
        });
    }
}
