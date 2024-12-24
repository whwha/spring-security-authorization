package nextstep.security.authorization;

public class AuthorizationDecision {
    private final boolean granted;

    public AuthorizationDecision(boolean granted) {
        this.granted = granted;
    }

    public boolean isGranted() {
        return granted;
    }
}
