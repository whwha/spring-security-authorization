package nextstep.app.application;

import nextstep.app.domain.MemberRepository;
import nextstep.security.userdetils.UserDetails;
import nextstep.security.userdetils.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;

    public CustomUserDetailsService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        return memberRepository.findByEmail(username)
                .map(member -> new UserDetails() {
                    @Override
                    public String getUsername() {
                        return member.getEmail();
                    }

                    @Override
                    public String getPassword() {
                        return member.getPassword();
                    }
                }).orElse(null);
    }
}
