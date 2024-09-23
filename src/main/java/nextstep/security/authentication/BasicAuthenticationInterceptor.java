package nextstep.security.authentication;

import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationException;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.UsernamePasswordAuthenticationToken;
import nextstep.security.context.SecurityContext;
import nextstep.security.context.SecurityContextHolder;
import org.springframework.http.HttpHeaders;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BasicAuthenticationInterceptor implements HandlerInterceptor {

    private final AuthenticationManager authenticationManager;

    public BasicAuthenticationInterceptor(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
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

            return true;
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            return false;
        }
    }

    private UsernamePasswordAuthenticationToken createAuthentication(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(authorization)) {
            return null;
        }

        if (!checkBasicAuth(authorization)) {
            return null;
        }

        String credential = extractCredential(authorization);
        String decodedCredential = new String(Base64Utils.decodeFromString(credential));
        String[] emailAndPassword = decodedCredential.split(":");

        String email = emailAndPassword[0];
        String password = emailAndPassword[1];

        return UsernamePasswordAuthenticationToken.unauthenticated(email, password);
    }

    private boolean checkBasicAuth(String authorization) {
        String[] split = authorization.split(" ");
        if (split.length != 2) {
            throw new AuthenticationException();
        }

        String type = split[0];
        return "Basic".equalsIgnoreCase(type);
    }

    private String extractCredential(String authorization) {
        String[] split = authorization.split(" ");
        if (split.length != 2) {
            throw new AuthenticationException();
        }

        return split[1];
    }
}
