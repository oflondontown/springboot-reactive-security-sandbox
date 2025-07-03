package ofl.sandbox.security.config;

import ofl.sandbox.security.jwt.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;

@Configuration
@Profile("webservice")
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
