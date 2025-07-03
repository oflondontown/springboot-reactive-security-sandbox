package ofl.sandbox.security.controller;

import ofl.sandbox.security.jwt.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api")
@Profile("dataservice")
public class DataServiceController {
    private static final String SERVICE_AUTH_HEADER = "x-service-auth";
    private static final String USER_AUTH_ID_HEADER = "x-login-id";
    private final JwtService jwtService;

    public DataServiceController(@Autowired JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/data")
    @PreAuthorize("hasAuthority('CAN_SEE_DATA')") // this validates the user token
    public Mono<ResponseEntity<String>> data(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader, // user jwt
            @RequestHeader(value = SERVICE_AUTH_HEADER) String serviceJwtToken) {
        final String userToken = authHeader.replace("Bearer ", "");

        // add another validation to verify the service token
        if(!jwtService.isValidServiceToken(serviceJwtToken, userToken, "WebService")) {
            return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).body(
                    "Invalid Service Token"
            ));
        }

        return Mono.just(ResponseEntity.ok("Here is some data"));
    }
}
