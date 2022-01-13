package com.yarda.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

// @EnableGlobalMethodSecurity(prePostEnabled = true) 开启全局方法安全校验注解
// 使用表达式时间方法级别的安全性4个注解可用
// @PreAuthorize 在方法调用之前, 基于表达式的计算结果来限制对方法的访问
// @PostAuthorize 允许方法调用, 但是如果表达式计算结果为false, 将抛出一个安全性异常
// @PostFilter 允许方法调用, 但必须按照表达式来过滤方法的结果
// @PreFilter 允许方法调用, 但必须在进入方法之前过滤输入值

/**
 * 认证服务器配置
 * @author xuezheng
 * @date 2022/1/6 14:40
 * @version  1.0
 */
@Configuration
@EnableWebSecurity  // 开启 Spring security 功能
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableAuthorizationServer  // 开启 Spring cloud oauth2 认证授权功能
public class AuthorizationServerConfig extends WebSecurityConfigurerAdapter {

    /** 密码编码器配置：BCryptPasswordEncoder */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
