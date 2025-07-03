package ofl.sandbox.security.controller;

import lombok.extern.slf4j.Slf4j;
import ofl.sandbox.security.jwt.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;

@RestController
@RequestMapping("/webservice/api")
@Profile("webservice")
@Slf4j
public class WebServiceController {
    private static final String SERVICE_AUTH_HEADER = "x-service-auth";
    private static final String USER_AUTH_ID_HEADER = "x-login-id";
    private final WebClient webClient;
    private final JwtService jwtService;

    private final String authServiceUrl;
    private final String dataServiceUrl;

    public WebServiceController(@Autowired WebClient webClient,
                           @Autowired JwtService jwtService,
                            @Value("${auth-service.url:http://localhost:8091}") String authServiceUrl,
                                @Value("${data-service.url:http://localhost:8092}") String dataServiceUrl) {
        this.jwtService = jwtService;
        this.webClient = webClient;
        this.authServiceUrl = authServiceUrl;
        this.dataServiceUrl = dataServiceUrl;
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<String>> login(@RequestHeader(value = USER_AUTH_ID_HEADER, required = false) String loginId) {
        if(loginId == null) {
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unknown login ID"));
        }

        log.info("Received login request for {}", loginId);
        final String serviceAuthToken = jwtService.issueServiceToken(loginId);
        log.info("Forwarding request to auth service with service token: '{}'", serviceAuthToken);

//        return Mono.just(ResponseEntity.ok(jwtService.issueUserToken(loginId, List.of("CAN_TRADE"))));

        return webClient.post()
                .uri(authServiceUrl + "/auth/api/token") // request Jwt from Auth Service
                .header(SERVICE_AUTH_HEADER,
                        "Bearer " + serviceAuthToken)
                .retrieve()
                .bodyToMono(String.class)
                .map(jwt -> ResponseEntity.ok().body(jwt));
    }

    @GetMapping("/data")
    @PreAuthorize("hasAuthority('CAN_TRADE')") // 'hasAuthority' checks GrantedAuthority objects
    public Mono<ResponseEntity<String>> trade(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        return webClient.post()
                .uri(dataServiceUrl + "/dataservice/api/data")
                .header(HttpHeaders.AUTHORIZATION, authHeader) // pass-through the user jwt --- no need to do this with the custom webClientWithJwt()
                .header(SERVICE_AUTH_HEADER, // and add a service jwt
                        "Bearer " + jwtService.issueServiceToken(jwtService.getUserTokenSubject(authHeader)))
                .retrieve()
                .bodyToMono(String.class)
                .map(jwt -> ResponseEntity.ok().body(jwt));
    }

}
