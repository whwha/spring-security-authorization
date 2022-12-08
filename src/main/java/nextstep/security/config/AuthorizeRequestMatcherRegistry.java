package nextstep.security.config;

import nextstep.security.access.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

public class AuthorizeRequestMatcherRegistry {
    private final Map<RequestMatcher, String> mappings = new HashMap<>();

    public AuthorizedUrl matcher(RequestMatcher requestMatcher) {
        return new AuthorizedUrl(requestMatcher);
    }

    AuthorizeRequestMatcherRegistry addMapping(RequestMatcher requestMatcher, String attributes) {
        mappings.put(requestMatcher, attributes);
        return this;
    }

    public String getAttribute(HttpServletRequest request) {
        for (Map.Entry<RequestMatcher, String> entry : mappings.entrySet()) {
            if (entry.getKey().matches(request)) {
                return entry.getValue();
            }
        }

        return null;
    }

    public class AuthorizedUrl {
        public static final String PERMIT_ALL = "permitAll";
        public static final String DENY_ALL = "denyAll";
        public static final String AUTHENTICATED = "authenticated";
        private final RequestMatcher requestMatcher;

        public AuthorizedUrl(RequestMatcher requestMatcher) {
            this.requestMatcher = requestMatcher;
        }

        public AuthorizeRequestMatcherRegistry permitAll() {
            return access(PERMIT_ALL);
        }

        public AuthorizeRequestMatcherRegistry denyAll() {
            return access(DENY_ALL);
        }

        public AuthorizeRequestMatcherRegistry hasAuthority(String authority) {
            return access("hasAuthority(" + authority + ")");
        }

        public AuthorizeRequestMatcherRegistry authenticated() {
            return access(AUTHENTICATED);
        }

        private AuthorizeRequestMatcherRegistry access(String attribute) {
            return addMapping(requestMatcher, attribute);
        }
    }

}
