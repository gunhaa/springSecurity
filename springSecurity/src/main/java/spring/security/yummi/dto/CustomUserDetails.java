package spring.security.yummi.dto;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import spring.security.yummi.entity.UserEntity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CustomUserDetails implements UserDetails {

    private UserEntity userEntity;

    public CustomUserDetails(UserEntity userEntity){
        this.userEntity = userEntity;
    };

    // 사용자의 권한을 리턴한다.
    // 직접 구현해야한다.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return userEntity.getRole();
            }
        });

        return collection;
    }

    // 객체에서 꺼낸다
    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    //객체에서 꺼낸다
    @Override
    public String getUsername() {
        return userEntity.getUsername();
    }

    // db에 값을 넣고 사용하는 메소드들이다.
    // db에 값이 없는 상태라면, true로 설정해서 사용하면된다.
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
