package nextstep.security.authorization;

import nextstep.security.access.hierarchicalroles.NullRoleHierarchy;
import nextstep.security.access.hierarchicalroles.RoleHierarchy;
import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationException;

import java.util.Collection;

public class AuthorityAuthorizationManager<T> implements AuthorizationManager<T> {
    private RoleHierarchy roleHierarchy = new NullRoleHierarchy();
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

        boolean isGranted = isGranted(authentication, authority);
        return new AuthorizationDecision(isGranted);
    }

    private boolean isGranted(Authentication authentication, String authority) {
        return authentication != null && isAuthorized(authentication, authority);
    }

    private boolean isAuthorized(Authentication authentication, String authority) {
        for (String grantedAuthority : getGrantedAuthorities(authentication)) {
            if (authority.equals(grantedAuthority)) {
                return true;
            }
        }
        return false;
    }

    private Collection<String> getGrantedAuthorities(Authentication authentication) {
        return this.roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
    }
}
