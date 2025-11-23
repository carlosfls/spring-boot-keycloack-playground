package org.carlosacademic.keycloackplayground.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Class to convert a JWT to an AuthenticationToken with the proper claims for spring security.
 */
@Component
public class JwtTokenConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Value("${resource-id}")
    private String resourceId;

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        List<String> roles = extractRolesFromJwt(jwt);
        List<SimpleGrantedAuthority> authorities = convertRolesToGrantedAuthorities(roles);
        String username = extractUsernameFromJwt(jwt);


        return new JwtAuthenticationToken(jwt, authorities, username);
    }

    /**
     * Extracts the roles from the JWT.
     * Accessing to the JSON in the jwt searching for the resource_access key and the resourceId.
     * Then access to the list of roles.
     * Example of the token: example.json in the resources' folder.
     *
     * @param jwt the token
     * @return the roles
     */
    private List<String> extractRolesFromJwt(Jwt jwt) {
        return Optional.ofNullable(jwt.getClaims().get("resource_access"))
                .map(access -> (Map<String, Object>) access)
                .map(accessMap -> (Map<String, Object>) accessMap.get(resourceId))
                .map(resourceMap -> (List<String>) resourceMap.get("roles"))
                .orElse(Collections.emptyList());
    }

    /**
     * Converts the roles to a list of granted authorities.
     * Add the prefix ROLE_ to the role for spring security to recognize it.
     *
     * @param roles The jwt extracted roles
     * @return The granted authorities
     */
    private List<SimpleGrantedAuthority> convertRolesToGrantedAuthorities(List<String> roles) {
        return roles.stream()
                .map(role -> "ROLE_"+role)
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    /**
     * Extracts the username from the JWT.
     * If the preferred_username claim is present, it will be used, otherwise the subject claim will be used.
     *
     * @param jwt The JWT
     * @return The username.
     */
    private String extractUsernameFromJwt(Jwt jwt) {
        if (jwt.getClaims().containsKey("preferred_username")) {
            return jwt.getClaims().get("preferred_username").toString();
        }
        return jwt.getSubject();
    }
}
