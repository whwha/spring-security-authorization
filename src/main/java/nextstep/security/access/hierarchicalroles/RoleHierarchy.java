package nextstep.security.access.hierarchicalroles;

import java.util.Collection;

public interface RoleHierarchy {
    Collection<String> getReachableGrantedAuthorities(Collection<String> authorities);
}
