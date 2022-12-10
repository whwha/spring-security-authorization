package nextstep.app.ui;

import nextstep.app.domain.MemberRepository;
import nextstep.app.ui.dto.MemberDto;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
public class MemberController {

    private final MemberRepository memberRepository;

    public MemberController(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @GetMapping("/members")
    public ResponseEntity<List<MemberDto>> list() {
        List<MemberDto> members = memberRepository.findAll()
                .stream()
                .map(member -> new MemberDto(
                        member.getEmail(),
                        member.getPassword(),
                        member.getName(),
                        member.getImageUrl(),
                        member.getRoles())
                )
                .collect(Collectors.toList());
        return ResponseEntity.ok(members);
    }

}
