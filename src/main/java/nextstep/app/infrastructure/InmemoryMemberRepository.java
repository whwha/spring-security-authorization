package nextstep.app.infrastructure;

import nextstep.app.domain.Member;
import nextstep.app.domain.MemberRepository;
import org.springframework.stereotype.Repository;

import java.util.*;
import java.util.stream.Collectors;

@Repository
public class InmemoryMemberRepository implements MemberRepository {
    public static final Member TEST_MEMBER_1 = new Member("a@a.com", "password", "a", "");
    public static final Member TEST_MEMBER_2 = new Member("b@b.com", "password", "b", "");
    private static final Map<String, Member> members = new HashMap<>();

    static {
        members.put(TEST_MEMBER_1.getEmail(), TEST_MEMBER_1);
        members.put(TEST_MEMBER_2.getEmail(), TEST_MEMBER_2);
    }

    @Override
    public Optional<Member> findByEmail(String email) {
        return Optional.ofNullable(members.get(email));
    }

    @Override
    public List<Member> findAll() {
        return members.values().stream().collect(Collectors.toUnmodifiableList());
    }
}
