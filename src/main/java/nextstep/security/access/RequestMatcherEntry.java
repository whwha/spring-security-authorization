package nextstep.security.access;

public class RequestMatcherEntry<T> {
    private final RequestMatcher requestMatcher;

    private final T entry;

    public RequestMatcherEntry(RequestMatcher requestMatcher, T entry) {
        this.requestMatcher = requestMatcher;
        this.entry = entry;
    }

    public RequestMatcher getRequestMatcher() {
        return this.requestMatcher;
    }

    public T getEntry() {
        return this.entry;
    }
}
