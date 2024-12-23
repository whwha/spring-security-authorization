package nextstep.security.authorization;

import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationException;
import nextstep.security.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthorizationFilter extends OncePerRequestFilter {

    private final RoleHierarchy roleHierarchy;

    public AuthorizationFilter(RoleHierarchy roleHierarchy) {
        this.roleHierarchy = roleHierarchy;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isGranted = checkAuthorization(authentication, request);

        if (!isGranted) {
            throw new ForbiddenException();
        }
        filterChain.doFilter(request, response);
    }

    private boolean checkAuthorization(Authentication authentication, HttpServletRequest request) {
        if (request.getRequestURI().equals("/members")) {
            if (authentication == null) {
                throw new AuthenticationException();
            }
            return authentication.getAuthorities()
                    .stream()
                    .anyMatch(authority -> roleHierarchy.check(authority, "ADMIN"));
        }

        if (request.getRequestURI().equals("/members/me")) {
            if (authentication == null) {
                throw new AuthenticationException();
            }
            return authentication.getAuthorities()
                    .stream()
                    .anyMatch(authority -> roleHierarchy.check(authority, "USER"));
        }

        if (request.getRequestURI().equals("/search")) {
            return true;
        }

        return false;
    }
}
