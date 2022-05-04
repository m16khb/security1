package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.domain.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class IndexController {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody String loginTest(@AuthenticationPrincipal PrincipalDetails principalDetails){
        System.out.println("principalDetails.getUser() = " + principalDetails.getUser());

        return "세션 정보 확인하기";
    }


    @GetMapping({"", "/"})
    public String index(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        //머스테치 기본폴더 src/main/resources/
        //view resolver : templates(prefix), .mustache(suffix)
        //로그인 유저 데이터 확인
        if (principalDetails != null) {
            for (GrantedAuthority authority : principalDetails.getAuthorities()) {
                System.out.println("authority = " + authority.getAuthority());
            }
            System.out.println(principalDetails.getUsername());
            System.out.println(bCryptPasswordEncoder.matches("zxc", principalDetails.getPassword()));
        }
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody
    String user() {
        return "user";
    }

    @GetMapping("/manager")
    public @ResponseBody
    String manager() {
        return "manager";
    }

    @GetMapping("/admin")
    public @ResponseBody
    String admin() {
        return "admin";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    //스프링 시큐리티가 해당 url을 낚아챔 - SecurityConfig 파일 생성후 낚아채지 않음
    @PostMapping("/login")
    public String login() {
        System.out.println("IndexController.login");
        return "login";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword); //비밀번호 암호화
        user.setPassword(encPassword);
        userRepository.save(user); //회원 가입 잘됨 . 비밀번호 암호화 안되었음 -> 시큐리티로 로그인을 할 수 가 없음
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody
    String info() {
        return "개인정보";
    }

    //권한을 여러개 걸고 싶을 때
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody
    String data() {
        return "데이터정보";
    }
}
