package ofl.sandbox.security.config;

import ofl.sandbox.security.jwt.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;

@Configuration
@Profile("webservice")
@ConditionalOnProperty(name = {"flux.enabled", "security.enabled"}, havingValue = "true")
public class WebServiceSecurityConfig extends CoreSecurityConfig {

    public WebServiceSecurityConfig(@Autowired JwtService jwtService) {
        super(jwtService);
    }

    @Override
    protected Customizer<ServerHttpSecurity.AuthorizeExchangeSpec> authorizeExchangeSpecCustomizer() {
        return ex -> ex
                .pathMatchers(
                        "/",
                        "/index.html",
                        "/favicon.ico",
                        "/auth/**",
                        "/ws/**",
                        "/static/**",
                        "/webservice/api/login").permitAll()
                .anyExchange().authenticated();
    }
}
