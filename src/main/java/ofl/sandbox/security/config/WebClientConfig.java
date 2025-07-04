package ofl.sandbox.security.config;

import io.netty.resolver.DefaultAddressResolverGroup;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.reactive.socket.client.ReactorNettyWebSocketClient;
import org.springframework.web.reactive.socket.client.WebSocketClient;
import org.springframework.web.reactive.socket.server.support.WebSocketHandlerAdapter;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.client.WebsocketClientSpec;

import static org.springframework.web.reactive.function.server.RouterFunctions.route;
import static org.springframework.web.reactive.function.server.ServerResponse.ok;

@Slf4j
@EnableWebFlux
@Configuration
@ConditionalOnProperty(name = "flux.enabled")
public class WebClientConfig implements WebFluxConfigurer {


    @Bean
    public RouterFunction<ServerResponse> routes() {
        return route()
                .GET("/helloworld", serverRequest -> ok().body(Flux.just("hello", "world"), String.class))
                .resources("/**", new ClassPathResource("static/"))
                .GET(this::isStaticRoute, this::routeToIndexHtml)
                .POST(this::isStaticRoute, this::routeToIndexHtml)
                .PUT(this::isStaticRoute, this::routeToIndexHtml)
                .DELETE(this::isStaticRoute, this::routeToIndexHtml)
                .after((request, response) -> {
                    log.info("Routing {} -> {}", request.toString(), response.toString());
                    return response;
                })
                .build();
    }

    protected boolean isStaticRoute(ServerRequest serverRequest) {
        return serverRequest.path().equals("/")
                || serverRequest.path().contains("index.html")
                || serverRequest.path().isEmpty();

    }

    protected Mono<ServerResponse> routeToIndexHtml(ServerRequest serverRequest) {
        return ok().contentType(MediaType.TEXT_HTML).bodyValue(new ClassPathResource("/static/index.html"));
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("*")
                .allowedMethods("*")
                .allowedHeaders("*")
                .exposedHeaders("*");
    }

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.addExposedHeader("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }

    @Bean
    public WebClient webClientWithJwt() {
        HttpClient httpClient = HttpClient.create()
                .resolver(DefaultAddressResolverGroup.INSTANCE);
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
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

    @Bean
    public WebSocketHandlerAdapter handlerAdapter() {
        return new WebSocketHandlerAdapter();
    }

    @Bean
    public WebSocketClient webSocketClient() {
        return new ReactorNettyWebSocketClient(
                HttpClient.create(), WebsocketClientSpec.builder());
    }
}
