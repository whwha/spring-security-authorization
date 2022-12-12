package nextstep.security.authentication;

import nextstep.security.context.SecurityContext;
import nextstep.security.context.SecurityContextHolder;
import nextstep.security.context.SecurityContextRepository;
import nextstep.security.exception.AuthorizationException;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

public class AuthorizationFilter extends GenericFilterBean {

    private final String role;
    private final SecurityContextRepository securityContextRepository;

    public AuthorizationFilter(String role, SecurityContextRepository securityContextRepository) {
        this.role = role;
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    public void doFilter(
            ServletRequest request,
            ServletResponse response,
            FilterChain chain
    ) throws IOException, ServletException {
        try {
            Set <String> roles = getRoles(request);

            if (!roles.contains(role)) {
                ((HttpServletResponse) response).sendError(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase());
                return;
            }
        } catch (AuthorizationException e) {
            ((HttpServletResponse) response).sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
            return;
        }

        chain.doFilter(request, response);
    }

    private Set<String> getRoles(ServletRequest request) {
        SecurityContext context = securityContextRepository.loadContext((HttpServletRequest) request);
        if (context != null) {
            return context.getAuthentication().getAuthorities();
        } else {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            return authentication.getAuthorities();
        }
    }
}
