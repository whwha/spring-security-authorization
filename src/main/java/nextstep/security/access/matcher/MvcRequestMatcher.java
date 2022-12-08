package nextstep.security.access.matcher;

import org.springframework.http.HttpMethod;

import javax.servlet.http.HttpServletRequest;

public class MvcRequestMatcher implements RequestMatcher {

    private HttpMethod method;
    private String pattern;

    public MvcRequestMatcher(HttpMethod method, String pattern) {
        this.method = method;
        this.pattern = pattern;
    }

    public HttpMethod getMethod() {
        return method;
    }

    public String getPattern() {
        return pattern;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        if (this.method != null && !this.method.name().equals(request.getMethod())) {
            return false;
        }

        return request.getRequestURI().equals(pattern);
    }
}
