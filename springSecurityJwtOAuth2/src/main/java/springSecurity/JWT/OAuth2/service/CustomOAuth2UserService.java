package springSecurity.JWT.OAuth2.service;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import springSecurity.JWT.OAuth2.dto.GoogleResponse;
import springSecurity.JWT.OAuth2.dto.NaverResponse;
import springSecurity.JWT.OAuth2.dto.OAuth2Response;

@Service
                                    // 상속받아서 특정 메소드(loadUser)를 오버라이딩해서
                                    // Accesstoken으로 유저정보를 획득하는 서비스를 구현할수 있다.
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Override
                                // 리소스 서버에서 제공되는 유저 정보
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException{

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("oAuth2User = " + oAuth2User);
        
        // 어디에서 온 값인지 확인
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;
        if(registrationId.equals("naver")){
            /* 네이버 데이터 : JSON
            {
                    resultcode=00, message=success, response={id=123123123, name=개발자유미}
            }
            */
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        }else if (registrationId.equals("google")){
            /* 구글 데이터 : JSON
            {
                    resultcode=00, message=success, sub=123123123, name=개발자유미
            }
            */
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        }else {
            return null;
        }
        return null;
    }

}
