package nextstep.app.application;

import nextstep.security.exception.AuthenticationException;
import nextstep.security.userdetails.BaseUser;
import nextstep.security.userdetails.UserDetails;
import nextstep.security.userdetails.UserDetailsService;
import nextstep.app.domain.Member;
import nextstep.app.domain.MemberRepository;
import org.springframework.stereotype.Service;

@Service
public class MemberUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;

    public MemberUserDetailsService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws AuthenticationException {
        Member member = memberRepository.findByEmail(username).orElseThrow(AuthenticationException::new);
        return new BaseUser(member.getEmail(), member.getPassword(), member.getRoles());
    }
}
