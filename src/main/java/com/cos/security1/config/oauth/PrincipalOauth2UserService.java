package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.domain.User;
import com.cos.security1.repository.UserRepository;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    @Autowired
    private UserRepository userRepository;

    //구글로부터 받은 userRequest 데이터에 대해 후처리되는 함수
    //함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        //구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 -> code를 리턴(OAuth-Client라이브러리) -> AccessToken요청
        //userRequest정보 -> loadUser함수 -> 구글로부터 회원 프로필 받아준다.

        System.out.println("oAuth2User = " + oAuth2User);
        OAuth2UserInfo oAuth2UserInfo = null;
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")){
            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        }else{
            System.out.println("우리는 구글과 페이스북만 지원해요");
        }


        String provider = oAuth2UserInfo.getProvider(); //google
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = new BCryptPasswordEncoder().encode("비밀번호");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        if(userEntity == null){
            if(provider.equals("google")){
                System.out.println("구글 로그인이 최초입니다.");
            }else if(provider.equals("facebook")){
                System.out.println("페이스북 로그인이 최초입니다.");
            }
            else if(provider.equals("naver")){
                System.out.println("네이버 로그인이 최초입니다.");
            }
            userEntity = User.builder()
                .username(username)
                .password(password)
                .email(email)
                .role(role)
                .provider(provider)
                .providerId(providerId)
                .build();
            userRepository.save(userEntity);
        }else{
            System.out.println("로그인을 이미 한적이 있습니다. 당신은 자동회원가입이 되어있습니다.");
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
