package nextstep.security.context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface SecurityContextRepository {

    SecurityContext loadContext(HttpServletRequest request);

    void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response);

}
