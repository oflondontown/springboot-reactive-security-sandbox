package ofl.sandbox.security.config;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import ofl.sandbox.security.jwt.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
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

@Data
@Slf4j
@Configuration
@ConfigurationProperties("prefix = blah")
@Profile("webservice")
@ConditionalOnProperty(name = {"flux.enabled", "security.enabled"}, havingValue = "true")
public class WebServiceSecurityConfig /*extends CoreSecurityConfig*/ {

    public WebServiceSecurityConfig(@Autowired JwtService jwtService) {
       // super(jwtService);
        this.jwtService = jwtService;
    }

    //@Override
    protected Customizer<ServerHttpSecurity.AuthorizeExchangeSpec> authorizeExchangeSpecCustomizer() {
        return ex -> {
                ex.pathMatchers(HttpMethod.OPTIONS).permitAll();
                ex.anyExchange().authenticated();
//                    .pathMatchers(
//                            "/",
//                            "/index.html",
//                            "/favicon.ico",
//                            "/auth/**",
//                            "/ws/**",
//                            "/static/**",
//                            "/webservice/api/login").permitAll()
//                    .anyExchange().authenticated();
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    private final JwtService jwtService;

    @Value("${security.enabled:}")
    private String securityEnabled;


    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
        log.info("initialised secure filter: securityEnabled: {}", securityEnabled);
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(authorizeExchangeSpecCustomizer())
                .exceptionHandling(ex -> ex
                        .accessDeniedHandler(customAccessDeniedHandler()))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(grantedAuthoritiesConverter()))
                )
                .build();
    }


    @Bean
    public MapReactiveUserDetailsService reactiveUserDetailsService() {
        return new MapReactiveUserDetailsService(
                User.builder()
                        .username("user")
                        .password(passwordEncoder().encode("password"))
                        .roles("USER")
                        .build()
        );
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager(
            MapReactiveUserDetailsService userDetailsService) {
        return new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
    }


    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        return NimbusReactiveJwtDecoder
                .withSecretKey(jwtService.getUserKey())
                .macAlgorithm(MacAlgorithm.HS384)
                .build();
    }


    protected ServerAccessDeniedHandler customAccessDeniedHandler() {
        return (ServerWebExchange exchange, AccessDeniedException denied) -> {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            byte[] bytes = "Access Denied".getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        };
    }

    /**
     * This is used for the @PreAuthorize "hasAuthority" logic
     * By default "hasAuthority" will validate a claim called "scope" or "authorities",
     * we are overriding this to check a claim called "entitlements"
     * @return
     */
    protected Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesConverter() {
        return jwt -> {
            Collection<GrantedAuthority> authorities = Optional.ofNullable(jwt.getClaimAsStringList("entitlements"))
                    .orElse(List.of())
                    .stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            return Mono.just(new JwtAuthenticationToken(jwt, authorities));
        };
    }
}
