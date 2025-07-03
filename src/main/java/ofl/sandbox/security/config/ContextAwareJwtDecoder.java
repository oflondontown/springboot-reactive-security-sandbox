//package ofl.sandbox.security.config;
//
//import ofl.sandbox.security.jwt.JwtService;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
//import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
//import reactor.core.publisher.Mono;
//
//import javax.crypto.SecretKey;
//
//public class ContextAwareJwtDecoder implements ReactiveJwtDecoder {
//
//    private final JwtService jwtService;
//    private final ServerRequestContext requestContext;
//
//    public ContextAwareJwtDecoder(JwtService jwtService,
//                                  ServerRequestContext requestContext) {
//        this.jwtService = jwtService;
//        this.requestContext = requestContext;
//    }
//
//    @Override
//    public Mono<Jwt> decode(String token) {
//        return Mono.defer(() -> {
//            String path = requestContext.getCurrentRequestPath();
//            SecretKey key = path.startsWith("/api/data")
//                    ? jwtService.getUserKey()
//                    : jwtService.getServiceKey();
//
//            NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withSecretKey(key).build();
//            return decoder.decode(token);
//        });
//    }
//}
