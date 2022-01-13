package com.yarda.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.annotation.Resource;

/**
 * 资源服务器配置
 * @author xuezheng
 * @version 1.0
 * @date 2022/1/12 15:48
 */
@Configuration
@EnableResourceServer // 开启 Spring cloud oauth2 资源服务功能
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    /** 认证失败处理 */
    @Resource
    private AuthenticationFailureHandler authenticationFailureHandler;
    /** 认证成功处理 */
    @Resource
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    /** 安全配置 */
    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .formLogin() // 表单登录
                // http.httpBasic() // HTTP Basic
                    .loginProcessingUrl("/login") // 处理表单登录 URL
                    .successHandler(authenticationSuccessHandler)
                    .failureHandler(authenticationFailureHandler)
                .and()
                    .authorizeRequests() // 授权配置
                    .anyRequest()  // 所有请求
                    .authenticated() // 都需要认证
                .and()
                    .csrf().disable(); // csrf禁用
    }

}
