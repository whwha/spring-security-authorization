package nextstep.security.authorization;

import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationException;

public class AuthorityAuthorizationManager<T> implements AuthorizationManager<T> {
    private final RoleHierarchy roleHierarchy;
    private final String authority;

    public AuthorityAuthorizationManager(RoleHierarchy roleHierarchy, String authority) {
        this.roleHierarchy = roleHierarchy;
        this.authority = authority;
    }

    @Override
    public AuthorizationDecision check(Authentication authentication, T object) {
        if (authentication == null) {
            throw new AuthenticationException();
        }

        boolean isGranted = authentication.getAuthorities().stream()
                .anyMatch(requestAuthority -> roleHierarchy.check(requestAuthority, authority));

        return new AuthorizationDecision(isGranted);
    }
}
