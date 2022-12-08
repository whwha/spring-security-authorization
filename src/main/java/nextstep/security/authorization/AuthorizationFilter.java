package nextstep.security.authorization;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import nextstep.security.context.SecurityContext;
import nextstep.security.context.SecurityContextRepository;
import nextstep.security.exception.AuthorizationException;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.GenericFilterBean;

public class AuthorizationFilter extends GenericFilterBean {

    private final SecurityContextRepository securityContextRepository;
    private final RoleManager roleManager;

    public AuthorizationFilter(SecurityContextRepository securityContextRepository, RoleManager roleManager) {
        this.securityContextRepository = securityContextRepository;
        this.roleManager = roleManager;
    }

    @Override
    public void doFilter(
        ServletRequest request,
        ServletResponse response,
        FilterChain chain
    ) throws IOException, ServletException {
        try {
            final SecurityContext context = securityContextRepository.loadContext((HttpServletRequest) request);
            if (context.getAuthentication().getAuthorities().stream().noneMatch(roleManager::hasRole)) {
                throw new AuthorizationException();
            }
        } catch (AuthorizationException e) {
            ((HttpServletResponse) response).sendError(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase());
            return;
        }

        chain.doFilter(request, response);
    }
}
