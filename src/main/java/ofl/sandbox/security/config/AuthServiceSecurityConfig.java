package ofl.sandbox.security.config;

import ofl.sandbox.security.jwt.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;

@Configuration
@Profile("auth")
public class AuthServiceSecurityConfig extends CoreSecurityConfig {

    public AuthServiceSecurityConfig(@Autowired JwtService jwtService) {
        super(jwtService);
    }

    @Override
    protected Customizer<ServerHttpSecurity.AuthorizeExchangeSpec> authorizeExchangeSpecCustomizer() {
        return ex -> ex
                .pathMatchers("/", "/**").permitAll()
//                .pathMatchers("/api/token").permitAll()
                .anyExchange().authenticated();
    }
}
