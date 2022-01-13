package com.yarda.security.service;

import com.yarda.security.domain.LoginUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

/**
 * Spring Security 认证：自定义认证过程。将该组件添加到容器中就能自动生效
 * @author xuezheng
 * @date 2022/1/6 14:59
 * @version 1.0
 */
@Component
public class UserDetailsServiceImpl implements UserDetailsService {

    @Resource
    public PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 根据 username 获取用户信息逻辑
        // 以下为 demo
        if ("username".equals(username)) {
            return new LoginUser("username", passwordEncoder.encode("88888888"));
        } else if("admin".equals(username)) {
            return new LoginUser("admin", passwordEncoder.encode("password"));
        } else {
            throw new UsernameNotFoundException("登录用户：" + username + " 不存在");
        }
    }
}
