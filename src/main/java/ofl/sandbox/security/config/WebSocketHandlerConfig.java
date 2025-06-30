package ofl.sandbox.security.config;

import ofl.sandbox.security.websocket.AuthenticatedWebSocketHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.HandlerMapping;
import org.springframework.web.reactive.handler.SimpleUrlHandlerMapping;
import org.springframework.web.reactive.socket.server.support.WebSocketHandlerAdapter;

import java.util.Map;

@Configuration
public class WebSocketHandlerConfig {

    @Bean
    public HandlerMapping webSocketMapping(AuthenticatedWebSocketHandler handler) {
        return new SimpleUrlHandlerMapping(Map.of("/ws/secure", handler), 10);
    }

    @Bean
    public WebSocketHandlerAdapter handlerAdapter() {
        return new WebSocketHandlerAdapter();
    }
}
