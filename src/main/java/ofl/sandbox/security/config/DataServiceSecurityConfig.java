package ofl.sandbox.security.config;

import ofl.sandbox.security.jwt.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;

@Configuration
@Profile("dataservice")
public class DataServiceSecurityConfig extends CoreSecurityConfig {

    public DataServiceSecurityConfig(@Autowired JwtService jwtService) {
        super(jwtService);
    }

    protected Customizer<ServerHttpSecurity.AuthorizeExchangeSpec> authorizeExchangeSpecCustomizer() {
        return exchanges -> exchanges.anyExchange().authenticated();
    }

}
