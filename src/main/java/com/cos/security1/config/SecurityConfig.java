package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인에 등록이 됩니다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //secured 어노테이션 활성화, preAuthorize라는 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;
    
    //해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
    @Bean
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }

    //1.코드 받기(인증), 2. 엑세스 토큰(권한), 3. 사용자 프로필 정보를 가져와서
    //4-1. 그 정보를 토대로 회원가입을 자동으로 진행 시키기도 함
    //4-2. 부족한 정보를 입력받음음    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() //로그인만 되면 들어갈 수 있는 주소
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
            .and()
                .formLogin()
                .loginPage("/loginForm")
                .usernameParameter("username")
                .loginProcessingUrl("/login")// /login주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행합니다.
                .defaultSuccessUrl("/")
            .and()
                .oauth2Login()
                .loginPage("/loginForm") //구글 로그인이 완료된 후의 후처리가 필요 함. Tip. 코드 X (액세스 토큰 + 사용자 프로필 정보(O))
                .userInfoEndpoint()
                .userService(principalOauth2UserService); //oauth의 loadUser에서 후처리
    }
}
