package ofl.sandbox.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Bean
    public WebClient webClientWithJwt(WebClient.Builder builder) {
//        /*
//         * This will automatically send the user's JWT to the backend,
//         *  assuming the user is authenticated via Spring Security.
//         */
//        return builder
//                .filter((request, next) -> ReactiveSecurityContextHolder.getContext()
//                        .map(SecurityContext::getAuthentication)
//                        .cast(JwtAuthenticationToken.class)
//                        .map(auth -> {
//                            String token = auth.getToken().getTokenValue();
//                            return ClientRequest.from(request)
//                                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
//                                    .build();
//                        })
//                        .defaultIfEmpty(request) // fallback if no auth context
//                        .flatMap(next::exchange)
//                )
//                .build();
        return builder.build();
    }
}
