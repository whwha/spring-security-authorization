package nextstep.security.authorization;

import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationException;

import javax.servlet.http.HttpServletRequest;

public class RequestAuthorizationManager implements AuthorizationManager<HttpServletRequest> {
    private final RoleHierarchy roleHierarchy;

    public RequestAuthorizationManager(RoleHierarchy roleHierarchy) {
        this.roleHierarchy = roleHierarchy;
    }

    @Override
    public AuthorizationDecision check(Authentication authentication, HttpServletRequest request) {
        if (request.getRequestURI().equals("/members")) {
            if (authentication == null) {
                throw new AuthenticationException();
            }
            boolean isGranted = authentication.getAuthorities()
                    .stream()
                    .anyMatch(authority -> roleHierarchy.check(authority, "ADMIN"));
            return new AuthorizationDecision(isGranted);
        }

        if (request.getRequestURI().equals("/members/me")) {
            if (authentication == null) {
                throw new AuthenticationException();
            }
            boolean isGranted = authentication.getAuthorities()
                    .stream()
                    .anyMatch(authority -> roleHierarchy.check(authority, "USER"));
            return new AuthorizationDecision(isGranted);
        }

        if (request.getRequestURI().equals("/search")) {
            return new AuthorizationDecision(true);
        }
        throw new ForbiddenException();
    }

}
