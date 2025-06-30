package ofl.sandbox.security.config;

import ofl.sandbox.security.jwt.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Configuration
@EnableReactiveMethodSecurity
public class SecurityConfig {

    private final JwtService jwtService;

    public SecurityConfig(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(
                                "/",
                                "/index.html",
                                "/favicon.ico",
                                "/auth/**",
                                "/ws/**",
                                "/static/**"
                        ).permitAll()
                        .anyExchange().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .accessDeniedHandler(customAccessDeniedHandler()))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(grantedAuthoritiesConverter()))
                )
                .cors(corsSpec -> corsSpec
                        .configurationSource(request -> {
                            CorsConfiguration config = new CorsConfiguration();
                            config.setAllowedOrigins(List.of("*"));
                            config.setAllowedMethods(List.of("*"));
                            config.setAllowedHeaders(List.of("*"));
                            return config;
                        })
                )
                .build();
    }

    private Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesConverter() {
        return jwt -> {
            Collection<GrantedAuthority> authorities = Optional.ofNullable(jwt.getClaimAsStringList("entitlements"))
                    .orElse(List.of())
                    .stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            return Mono.just(new JwtAuthenticationToken(jwt, authorities));
        };
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        return NimbusReactiveJwtDecoder.withSecretKey(jwtService.getKey()).build();
    }

    @Bean
    public ServerAccessDeniedHandler customAccessDeniedHandler() {
        return (ServerWebExchange exchange, AccessDeniedException denied) -> {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            byte[] bytes = "Access Denied".getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        };
    }
}
