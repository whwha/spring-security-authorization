package nextstep.security.authentication;

import nextstep.security.access.matcher.MvcRequestMatcher;
import nextstep.security.context.SecurityContext;
import nextstep.security.context.SecurityContextHolder;
import nextstep.security.context.SecurityContextRepository;
import nextstep.security.exception.AuthenticationException;
import nextstep.security.exception.AuthorizationException;
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

public class UsernamePasswordAuthenticationFilter extends GenericFilterBean {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private static final MvcRequestMatcher DEFAULT_REQUEST_MATCHER = new MvcRequestMatcher(HttpMethod.POST,
            "/login");

    public UsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager, SecurityContextRepository securityContextRepository) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        try {
            if (!DEFAULT_REQUEST_MATCHER.matches((HttpServletRequest) request)) {
                chain.doFilter(request, response);
                return;
            }

            String username = request.getParameter("username");
            String password = request.getParameter("password");

            UsernamePasswordAuthentication authRequest = UsernamePasswordAuthentication.ofRequest(username,
                    password);
            Authentication authResult = authenticationManager.authenticate(authRequest);

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authResult);
            SecurityContextHolder.setContext(context);

            securityContextRepository.saveContext(context, (HttpServletRequest) request, (HttpServletResponse) response);

            if (authResult.getAuthorities().isEmpty()) {
                throw new AuthorizationException();
            }
        } catch (AuthenticationException e) {
            SecurityContextHolder.clearContext();
            ((HttpServletResponse) response).sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
            return;
        } catch (AuthorizationException e) {
            ((HttpServletResponse) response).sendError(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase());
            return;
        }

        chain.doFilter(request, response);
    }
}
