package nextstep.security.userdetails;

import java.io.Serializable;
import java.util.Set;

public interface UserDetails extends Serializable {
    String getUsername();

    String getPassword();

    Set<String> getAuthorities();
}
