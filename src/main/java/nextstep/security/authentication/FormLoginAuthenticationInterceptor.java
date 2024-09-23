package nextstep.security.authentication;

import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.UsernamePasswordAuthenticationToken;
import nextstep.security.context.HttpSessionSecurityContextRepository;
import nextstep.security.context.SecurityContext;
import nextstep.security.context.SecurityContextHolder;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

public class FormLoginAuthenticationInterceptor implements HandlerInterceptor {

    private final AuthenticationManager authenticationManager;
    private final HttpSessionSecurityContextRepository securityContextRepository;

    public FormLoginAuthenticationInterceptor(AuthenticationManager authenticationManager, HttpSessionSecurityContextRepository securityContextRepository) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        try {
            UsernamePasswordAuthenticationToken authRequest = createAuthentication(request);
            if (authRequest == null) {
                return true;
            }

            Authentication authResult = authenticationManager.authenticate(authRequest);

            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(authResult);
            SecurityContextHolder.setContext(securityContext);

            securityContextRepository.saveContext(securityContext, request, response);

            return false;
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            return false;
        }
    }

    private UsernamePasswordAuthenticationToken createAuthentication(HttpServletRequest request) {
        try {
            Map<String, String[]> paramMap = request.getParameterMap();
            String email = paramMap.get("username")[0];
            String password = paramMap.get("password")[0];

            return UsernamePasswordAuthenticationToken.unauthenticated(email, password);
        } catch (Exception e) {
            return null;
        }
    }
}
