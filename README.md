# Secure WebFlux Backend with JWT and WebSocket Authorization

This project implements a secure reactive backend using **Spring Boot WebFlux**, where both REST and WebSocket endpoints are protected using **JWT tokens** with user entitlements.

# Technologies and Dependencies

| Library                                  | Details                                                               |
| ---------------------------------------- |-----------------------------------------------------------------------|
| `spring-boot-starter-webflux`            | Core WebFlux support for reactive REST and WebSocket APIs             |
| `spring-boot-starter-security`           | Enables Spring Security for REST and WebSocket endpoints              |
| `jjwt` (`io.jsonwebtoken:jjwt`)          | JWT generation and validation (signing, parsing, claim extraction)    |
| `spring-security-oauth2-jose`            | JWT decoder support integrated with Spring Security                   |
| `spring-security-oauth2-resource-server` | Support for validating bearer tokens in resource servers              |
| `reactor-core` (via WebFlux)             | Reactor framework for non-blocking programming (`Mono`, `Flux`, etc.) |


## Features

- Stateless JWT authentication with no external auth server.
- Custom login flow via `X-Login-Id` header mapped to backend entitlements.
- Role-based REST access control using `@PreAuthorize`.
- WebSocket endpoint `/ws/secure` with manual entitlement validation.
- Rejection messages sent to client before WebSocket is closed.
- Functional and annotation-based security configuration.

## Authentication Flow

1. A client initiates authentication by sending a request to `/auth/login` with a custom header:
2. The server checks the login ID against an internal map of users to entitlements.
3. If valid, the server generates and signs a JWT token that includes:
- `sub`: the login ID
- `entitlements`: list of authorities/permissions (e.g., `CAN_VIEW_MARKET`, `CAN_CONNECT_WS`)

4. The token is returned to the client:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6..."
}
```
5. The client uses this token in:
- REST API calls via Authorization: Bearer <token>
- WebSocket connections via ?token=<token> query parameter

### Sample Endpoint

```java
@RestController
@RequestMapping("/api")
public class SampleApi {

    @GetMapping("/hello")
    @PreAuthorize("hasAuthority('CAN_VIEW_MARKET')")
    public String hello() {
        return "Hello, market!";
    }
}
```

*Behaviour*
- Requests without a valid JWT return 401 Unauthorized.
- Requests with a valid JWT but lacking the required entitlement return 403 Forbidden.
- Valid tokens with required entitlements grant access to the endpoint.

### Login Endpoint

Send an HTTP `POST` to `/auth/login` with a custom header:

## Websocket Endpoint Protection

```
/ws/secure?token=<JWT>
```

*Behaviour*
- The JWT is extracted from the query parameter.
- If the token is invalid or missing, the server sends an error message and closes the connection.
- If the token is valid but lacks required entitlements (e.g., CAN_CONNECT_WS), the server also rejects the connection.
- Valid tokens with CAN_CONNECT_WS entitlement establish a successful WebSocket session.

### Sample Logic
```java
@Override
public Mono<Void> handle(WebSocketSession session) {
    String token = extractToken(session); // Extract from query

    if (!jwtService.isValid(token)) {
        return session.send(Mono.just(session.textMessage("Error: Invalid token")))
                     .then(session.close(CloseStatus.NORMAL.withReason("Unauthorized")));
    }

    List<String> entitlements = jwtService.getEntitlements(token);
    if (!entitlements.contains("CAN_CONNECT_WS")) {
        return session.send(Mono.just(session.textMessage("Error: Missing entitlement")))
                     .then(session.close(CloseStatus.NORMAL.withReason("Forbidden")));
    }

    return session.send(
        session.receive()
               .map(msg -> session.textMessage("Echo: " + msg.getPayloadAsText()))
    );
}

```


## Acceptance Criteria
| ID	 | Description                                                                  |
|-----|------------------------------------------------------------------------------|
| A1	 | JWT is issued for known X-Login-Id.                                          |
| A2	 | REST API accepts valid JWT with required entitlement.                        |
| A3	 | REST API rejects token missing required entitlement with HTTP 403.           |
| A4	 | WebSocket connection accepted with valid JWT and correct entitlement.        |
| A5	 | WebSocket sends error message and closes on invalid or unauthorized token.   |
| A6	 | Unauthorized routes are protected by Spring Security.                        |
| A7  | 	/auth/**, /index.html, and /ws/** are permitted for unauthenticated access. |

## Key Java Annotations

### Spring Security
| Annotation               | Description                                                                                                                                                                  |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@PreAuthorize(...)`     | Used on REST controller methods to restrict access based on user authorities (entitlements extracted from JWT). Example: `@PreAuthorize("hasAuthority('CAN_VIEW_MARKET')")`. |
| `@EnableWebFluxSecurity` | Enables Spring Security configuration in WebFlux applications.                                                                                                               |


---

## Technical Requirements

### Authentication

- Add an endpoint POST /auth/login that accepts a custom HTTP header:
```
X-Login-Id: <login-id>
```   
- The login ID is validated against an internal map (mocked for now).
- If valid, return a signed JWT containing:
-- sub: login ID
-- entitlements: list of permissions (e.g., CAN_VIEW_MARKET, CAN_CONNECT_WS)
- No passwords or external authentication server.

### JWT Token Handling
- Use HMAC (symmetric) signing for JWTs (e.g., HS256 via jjwt).
- JWTs are passed by clients using the standard HTTP Authorization: Bearer <token> header.
- Token parsing and verification must extract entitlements and map them to Spring GrantedAuthority objects.
- Token expiry must be enforced.

### REST API Authorization
- All non-/auth/**, /index.html, /ws/** endpoints must be secured via Spring Security.
- Use ```@PreAuthorize``` annotations on controllers to enforce entitlement-based access control.

#### Example:

```java
@PreAuthorize("hasAuthority('CAN_VIEW_MARKET')")
@GetMapping("/api/hello")
public String hello() { return "Hello, market!"; }
```

### WebSocket Endpoint Authorization
- WebSocket endpoint: ```/ws/secure```
- Token must be passed via query parameter: ```?token=...```
- Server must:
-- Extract and validate the token
-- Check for a required entitlement: CAN_CONNECT_WS
-- If unauthorized:
--- Send an error message (session.send(...))
--- Then close the connection (session.close(...))

### Spring Security Configuration
- Use _spring-security-oauth2-resource-server_ and _spring-security-oauth2-jose_ to handle JWT decoding.
- Permit unauthenticated access to:
-- /auth/**
-- /ws/**
-- /index.html, /favicon.ico
- All other endpoints require valid JWTs and appropriate authorities.

## Deliverables
- Secure JWT-based login and token usage
- REST endpoint with @PreAuthorize authorization
- WebSocket handler with manual entitlement check and error messaging
- Security configuration with route-level access control
- Minimal error handling (401 for invalid token, 403 for denied access)
- README with documentation