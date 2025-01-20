package springSecurity.JWT.OAuth2.service;

import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import springSecurity.JWT.OAuth2.dto.*;
import springSecurity.JWT.OAuth2.entity.UserEntity;
import springSecurity.JWT.OAuth2.repository.UserRepository;

@Service
                                    // 상속받아서 특정 메소드(loadUser)를 오버라이딩해서
                                    // Accesstoken으로 유저정보를 획득하는 서비스를 구현할수 있다.
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {


    private final UserRepository userRepository;

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

                        // 리소스 서버에서 발급 받은 정보로 사용자를 특정할 아이디 값을 만듬
        String username = oAuth2Response.getProvider()+" "+oAuth2Response.getProviderId();

        // username은 존재하는가?
        UserEntity existData = userRepository.findByUsername(username);

        if(existData == null){

            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setEmail(oAuth2Response.getEmail());
            userEntity.setName(oAuth2User.getName());
            userEntity.setRole("ROLE_USER");
            userRepository.save(userEntity);

            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(username);
            userDTO.setName(oAuth2Response.getName());
            userDTO.setRole("ROLE_USER");
            return new CustomOAuth2User(userDTO);

        }else{

            existData.setEmail(oAuth2Response.getEmail());
            existData.setName(oAuth2User.getName());
            userRepository.save(existData);

            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(existData.getUsername());
            userDTO.setName(oAuth2Response.getName());
            userDTO.setRole(existData.getRole());
            // 인터페이스를 implements해서 리턴값을 넘겨야해서 해당 방식으로 구현한다.
            return new CustomOAuth2User(userDTO);
        }

    }

}
