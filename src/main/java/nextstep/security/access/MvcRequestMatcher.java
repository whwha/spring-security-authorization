package nextstep.security.access;

import org.springframework.http.HttpMethod;

import javax.servlet.http.HttpServletRequest;

public class MvcRequestMatcher implements RequestMatcher {

    private final HttpMethod method;
    private final String pattern;

    public MvcRequestMatcher(HttpMethod method, String pattern) {
        this.method = method;
        this.pattern = pattern;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        if (method != null && !method.name().equals(request.getMethod())) {
            return false;
        }
        return request.getRequestURI().equals(pattern);
    }

    public HttpMethod getMethod() {
        return method;
    }

    public String getPattern() {
        return pattern;
    }
}
