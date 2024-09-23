package nextstep.security.context;

import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SecurityContextHolderInterceptor implements HandlerInterceptor {
    private final HttpSessionSecurityContextRepository securityContextRepository;

    public SecurityContextHolderInterceptor(HttpSessionSecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    public boolean preHandle(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, Object handler) {
        SecurityContext context = this.securityContextRepository.loadContext(request);
        SecurityContextHolder.setContext(context);
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        SecurityContextHolder.clearContext();
    }
}
