package nextstep.security.authorization;

import nextstep.security.access.matcher.MvcRequestMatcher;
import nextstep.security.authentication.Authentication;
import nextstep.security.context.SecurityContextHolder;
import nextstep.security.exception.AuthenticationException;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RoleAuthorizationFilter extends GenericFilterBean {
    private static final MvcRequestMatcher DEFAULT_REQUEST_MATCHER = new MvcRequestMatcher(HttpMethod.GET,
            "/members");

    private static final String ADMIN_ROLE = "ADMIN";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            if (!DEFAULT_REQUEST_MATCHER.matches((HttpServletRequest) request)) {
                chain.doFilter(request, response);
                return;
            }

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (!authentication.getAuthorities().contains(ADMIN_ROLE)) {
                ((HttpServletResponse) response).sendError(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase());
                return;
            }

        } catch (AuthenticationException e) {
            ((HttpServletResponse) response).sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
            return;
        }

        chain.doFilter(request, response);
    }

}
