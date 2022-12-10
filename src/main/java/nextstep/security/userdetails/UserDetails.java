package nextstep.security.userdetails;

import nextstep.security.authentication.Role;

import java.io.Serializable;
import java.util.Set;

public interface UserDetails extends Serializable {
    String getUsername();

    String getPassword();

    Set<Role> getRoles();
}
