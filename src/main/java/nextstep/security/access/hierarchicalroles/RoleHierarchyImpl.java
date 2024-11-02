package nextstep.security.access.hierarchicalroles;

import org.springframework.util.Assert;

import java.util.*;

public class RoleHierarchyImpl implements RoleHierarchy {
    private Map<String, Set<String>> rolesReachableInOneOrMoreStepsMap = null;

    private RoleHierarchyImpl(Map<String, Set<String>> hierarchy) {
        this.rolesReachableInOneOrMoreStepsMap = buildRolesReachableInOneOrMoreStepsMap(hierarchy);
    }

    public static Builder with() {
        return new Builder();
    }

    @Override
    public Collection<String> getReachableGrantedAuthorities(Collection<String> authorities) {
        if (authorities == null || authorities.isEmpty()) {
            return List.of();
        }
        Set<String> reachableRoles = new HashSet<>();
        Set<String> processedNames = new HashSet<>();
        for (String authority : authorities) {
            // Do not process authorities without string representation
            if (authority.isBlank()) {
                reachableRoles.add(authority);
                continue;
            }
            // Do not process already processed roles
            if (!processedNames.add(authority)) {
                continue;
            }
            // Add original authority
            reachableRoles.add(authority);
            // Add roles reachable in one or more steps
            Set<String> lowerRoles = this.rolesReachableInOneOrMoreStepsMap.get(authority);
            if (lowerRoles == null) {
                continue; // No hierarchy for the role
            }
            for (String role : lowerRoles) {
                if (processedNames.add(role)) {
                    reachableRoles.add(role);
                }
            }
        }
        return new ArrayList<>(reachableRoles);
    }

    private static Map<String, Set<String>> buildRolesReachableInOneOrMoreStepsMap(
            Map<String, Set<String>> hierarchy) {
        Map<String, Set<String>> rolesReachableInOneOrMoreStepsMap = new HashMap<>();
        // iterate over all higher roles from rolesReachableInOneStepMap
        for (String roleName : hierarchy.keySet()) {
            Set<String> rolesToVisitSet = new HashSet<>(hierarchy.get(roleName));
            Set<String> visitedRolesSet = new HashSet<>();
            while (!rolesToVisitSet.isEmpty()) {
                // take a role from the rolesToVisit set
                String lowerRole = rolesToVisitSet.iterator().next();
                rolesToVisitSet.remove(lowerRole);
                if (!visitedRolesSet.add(lowerRole) || !hierarchy.containsKey(lowerRole)) {
                    continue; // Already visited role or role with missing hierarchy
                } else if (roleName.equals(lowerRole)) {
                    throw new RuntimeException();
                }
                rolesToVisitSet.addAll(hierarchy.get(lowerRole));
            }
            rolesReachableInOneOrMoreStepsMap.put(roleName, visitedRolesSet);
        }
        return rolesReachableInOneOrMoreStepsMap;
    }

    public static final class Builder {

        private final Map<String, Set<String>> hierarchy;

        private Builder() {
            this.hierarchy = new LinkedHashMap<>();
        }

        /**
         * Creates a new hierarchy branch to define a role and its child roles.
         *
         * @param role the highest role in this branch
         * @return a {@link ImpliedRoles} to define the child roles for the
         * <code>role</code>
         */
        public ImpliedRoles role(String role) {
            Assert.hasText(role, "role must not be empty");
            return new ImpliedRoles(role);
        }

        /**
         * Builds and returns a {@link RoleHierarchyImpl} describing the defined role
         * hierarchy.
         *
         * @return a {@link RoleHierarchyImpl}
         */
        public RoleHierarchyImpl build() {
            return new RoleHierarchyImpl(this.hierarchy);
        }

        private Builder addHierarchy(String role, String... impliedRoles) {
            Set<String> withPrefix = new HashSet<>();
            for (String impliedRole : impliedRoles) {
                withPrefix.add(impliedRole);
            }
            this.hierarchy.put(role, withPrefix);
            return this;
        }

        /**
         * Builder class for constructing child roles within a role hierarchy branch.
         */
        public final class ImpliedRoles {

            private final String role;

            private ImpliedRoles(String role) {
                this.role = role;
            }

            /**
             * Specifies implied role(s) for the current role in the hierarchy.
             *
             * @param impliedRoles role name(s) implied by the role.
             * @return the same {@link Builder} instance
             * @throws IllegalArgumentException if <code>impliedRoles</code> is null,
             *                                  empty or contains any null element.
             */
            public Builder implies(String... impliedRoles) {
                Assert.notEmpty(impliedRoles, "at least one implied role must be provided");
                Assert.noNullElements(impliedRoles, "implied role name(s) cannot be empty");
                return Builder.this.addHierarchy(this.role, impliedRoles);
            }

        }

    }
}
