package org.carlosacademic.keycloackplayground.jwt;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Class to convert a JWT to an AuthenticationToken with the proper roles for spring security.
 */
@Component
public class JwtTokenConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();

    /**
     * Convert a JWT to an AuthenticationToken with the proper roles for spring security.
     * If the token is a client token (has the client_id claim), it executes the client flow.
     * Otherwise, executes the user flow.
     *
     * @param jwt The JWT to convert.
     * @return The AuthenticationToken.
     */
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        if (jwt.hasClaim("client_id")) {
            return createClientJwtAuthenticationToken(jwt);
        }

        return createUserJwtAuthenticationToken(jwt);
    }

    /**
     * Create a client JWT authentication token.
     * Get the scopes from the JWT and convert them to roles for spring security to recognize.
     *
     * @param jwt The JWT to convert.
     * @return The AuthenticationToken for the client api.
     */
    private JwtAuthenticationToken createClientJwtAuthenticationToken(Jwt jwt) {
        Collection<GrantedAuthority> grantedAuthorities = converter.convert(jwt);
        List<SimpleGrantedAuthority> authorities = transformScopesToRoles(grantedAuthorities);
        String clientId = getClientIdClaim(jwt);

        return new JwtAuthenticationToken(jwt, authorities, clientId);
    }

    /**
     * Create a user JWT authentication token.
     * Get the resource access from the JWT and inside them get the roles.
     * Convert the roles to spring security roles.
     * In this case we not use the scopes only the roles from the resource access.
     *
     * @param jwt The JWT to convert.
     * @return The AuthenticationToken for the user api.
     */
    private JwtAuthenticationToken createUserJwtAuthenticationToken(Jwt jwt) {
        String username = getUsernameClaim(jwt);
        Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
        if (resourceAccess != null) {
            Map<String, Object> resource = (Map<String, Object>) resourceAccess.get("keycloack-playground-api");
            if (resource != null) {
                List<String> roles = (List<String>) resource.get("roles");
                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(role -> "ROLE_" + role)
                        .map(SimpleGrantedAuthority::new)
                        .toList();

                return new JwtAuthenticationToken(jwt, authorities, username);
            }
        }
        return null;
    }

    /**
     * Transform the granted authorities with the prefix SCOPES to roles for spring security to recognize.
     *
     * @param grantedAuthorities The granted authorities from the JWT.
     * @return The list of roles.
     */
    private List<SimpleGrantedAuthority> transformScopesToRoles(Collection<GrantedAuthority> grantedAuthorities) {
        return grantedAuthorities
                .stream()
                .filter(a -> a.getAuthority().startsWith("SCOPE_"))
                .map(a -> a.getAuthority().replaceAll("SCOPE_","ROLE_"))
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    private String getClientIdClaim(Jwt token) {
        return token.getClaimAsString("client_id");
    }

    private String getUsernameClaim(Jwt token) {
        return token.getClaimAsString("preferred_username");
    }
}
