package nextstep.security.authentication;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class AuthenticationException extends RuntimeException {
    public AuthenticationException() {
        super("인증에 실패하였습니다.");
    }

    public AuthenticationException(String message) {
        super(message);
    }
}
