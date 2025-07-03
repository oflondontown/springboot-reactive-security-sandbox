//package ofl.sandbox.security.config;
//
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.stereotype.Component;
//
//@Component
//public class ServerRequestContext {
//
//    private static final ThreadLocal<ServerHttpRequest> requestHolder = new ThreadLocal<>();
//
//    public void set(ServerHttpRequest request) {
//        requestHolder.set(request);
//    }
//
//    public String getCurrentRequestPath() {
//        ServerHttpRequest request = requestHolder.get();
//        return request != null ? request.getPath().toString() : "";
//    }
//
//    public void clear() {
//        requestHolder.remove();
//    }
//}
