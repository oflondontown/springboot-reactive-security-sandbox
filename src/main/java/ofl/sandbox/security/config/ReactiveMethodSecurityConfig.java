package ofl.sandbox.security.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;

@Configuration
@EnableReactiveMethodSecurity
@ConditionalOnProperty(name = {"flux.enabled", "security.enabled"}, havingValue = "true")
public class ReactiveMethodSecurityConfig {
}
