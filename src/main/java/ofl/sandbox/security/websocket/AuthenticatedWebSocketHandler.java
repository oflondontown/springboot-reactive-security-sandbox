package ofl.sandbox.security.websocket;

import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import ofl.sandbox.security.jwt.JwtService;
import ofl.sandbox.security.service.UserEntitlementsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.socket.*;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.Optional;

@Slf4j
@Component
@Profile("webservice")
public class AuthenticatedWebSocketHandler implements WebSocketHandler {

    private final JwtService jwtService;
    private final UserEntitlementsService userEntitlementsService;

    public AuthenticatedWebSocketHandler(@Autowired JwtService jwtService,
                                         @Autowired UserEntitlementsService userEntitlementsService) {
        this.jwtService = jwtService;
        this.userEntitlementsService = userEntitlementsService;
    }

    @Override
    public Mono<Void> handle(WebSocketSession session) {
        URI uri = session.getHandshakeInfo().getUri();
        Optional<String> userToken = getTokenFromUri(uri);

        if (userToken.isEmpty()) {
            log.error("Token is empty");
            return handleInvalidConnection(session, CloseStatus.BAD_DATA, "Token is empty");
        }
        String userId = jwtService.getUserTokenSubject(userToken.get());

        try {
            List<String> entitlements = userEntitlementsService.getEntitlements(userId);

            if(!entitlements.contains("CAN_CONNECT_WS")) {
                log.error("Not entitled for WS");
                return handleInvalidConnection(session, CloseStatus.NOT_ACCEPTABLE, "Missing entitlement: CAN_CONNECT_WS");
            }

        } catch(JwtException e) {
            log.error("Bad token", e);
            return session.close(CloseStatus.BAD_DATA);
        }

        log.info("Sending to {}", userId);
        return session.send(session.receive()
                .map(msg -> session.textMessage("Echo from " + userId + ": " + msg.getPayloadAsText())));
    }

    private Mono<Void> handleInvalidConnection(WebSocketSession session, CloseStatus closeStatus, String invalidReason) {
        return session.send(Mono.just(
                session.textMessage(invalidReason)
        )).then(session.close(closeStatus.withReason(invalidReason)));
    }

    private Optional<String> getTokenFromUri(URI uri) {
        List<String> queryParts = List.of(uri.getQuery().split("&"));
        return queryParts.stream()
                .filter(q -> q.startsWith("token="))
                .map(q -> q.substring(6))
                .findFirst();
    }
}
