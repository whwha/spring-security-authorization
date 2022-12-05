package nextstep.security.context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class HttpSessionSecurityContextRepository implements SecurityContextRepository {
    public static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

    @Override
    public SecurityContext loadContext(HttpServletRequest request) {
        HttpSession httpSession = request.getSession();
        Object contextFromSession = httpSession.getAttribute(SPRING_SECURITY_CONTEXT_KEY);
        return contextFromSession == null ? null : (SecurityContext) contextFromSession;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        HttpSession httpSession = request.getSession();
        httpSession.setAttribute(SPRING_SECURITY_CONTEXT_KEY, context);
    }
}
