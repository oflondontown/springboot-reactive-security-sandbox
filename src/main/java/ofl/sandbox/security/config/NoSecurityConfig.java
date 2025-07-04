package ofl.sandbox.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Slf4j
@Configuration
@ConditionalOnProperty(name = "security.enabled", havingValue = "false", matchIfMissing = true)
public class NoSecurityConfig {


    @Value("${security.enabled:}")
    private String securityEnabled;

    @Bean
    public SecurityWebFilterChain permitAllSecurityWebFilterChain(ServerHttpSecurity http) {
        log.info("initialised insecure filter: securityEnabled: {}", securityEnabled);
        return http
                .authorizeExchange(ex ->
                        ex.anyExchange().permitAll())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .build();
    }
}
