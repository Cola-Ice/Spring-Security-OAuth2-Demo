# Spring Security OAuth2 学习示例代码

### Spring Security

两大核心功能：Authentication and Access Control

pom依赖：

```pom
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

#### 开启Spring Security

**基于的HTTP认证**

当 Spring 项目引入 Spring Security 依赖的时候，项目会默认开启如下配置：

```yaml
security:
  basic:
    enabled: true
```

这个配置开启了一个HTTP basic类型的认证，所有服务的访问都必须先过这个认证

**基于表单认证**

我们可以通过配置将HTTP basic认证修改为基于表单的认证方式

```java
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() // 表单方式
                .and()
                .authorizeRequests() // 授权配置
                .anyRequest()  // 所有请求
                .authenticated(); // 都需要认证
    }
}
```

**基本原理**

**![image-20220106171300753](https://github.com/Cola-Ice/Spring-Security-OAuth2-Demo/raw/master/doc/image/image-20220106171300753.png)**

认证流程：
![image-20220107163259377](https://github.com/Cola-Ice/Spring-Security-OAuth2-Demo/raw/master/doc/image/image-20220107163259377.png)

鉴权流程：
![image-20220107173316362](https://github.com/Cola-Ice/Spring-Security-OAuth2-Demo/raw/master/doc/image/image-20220107173316362.png)

如上图所示，Spring Security 包含了众多的过滤器，这些过滤器形成了一条链，所有请求都必须通过这些过滤器才能成功访问到资源。其中

`UsernamePasswordAuthenticationFilter`：处理基于表单方式的登录认证。将请求信息封装为`Authentication`，实现类为 `UsernamePasswordAuthenticationToken`，并将其交由`AuthenticationManager` 认证（详见该过滤器中 `attemptAuthentication()` 方法）

`BasicAuthenticationFilter`：处理基于HTTP Basic方式的登录验证。同理也会将请求信息封装为`UsernamePasswordAuthenticationToken`，并将其交由`AuthenticationManager` 认证

`AuthenticationManager`：调用该类的`authenticate()`方法进行认证，该方法会通过子类 `ProviderManager`，经过辗转找到对应类型的`AuthenticationProvider `，`AuthenticationProvider `获取用户信息并核对认证，最后重新封装 `Authentication` 返回给最开始的认证处理过滤器（例如：`UsernamePasswordAuthenticationFilter`）

`AuthenticationProvider `：每个 `AuthenticationProvider ` 都会实现 `support()` 方法，表明自己支持的认证类型

`FilterSecurityInterceptor`：过滤链尾部的拦截器，判断当前请求身份认证是否成功 ，用户认证成功则获取 `ConfigAttribute` ，继续调用访问控制器 `AccessDecisionManager` 对当前请求进行鉴权，当身份认证失败或权限不足时会抛出相应异常

`ExceptionTranslateFilter`：捕获`FilterSecurityInterceptor`抛出的异常并进行处理。但他只会处理两类异常：`AuthenticationException` 和 `AccessDeniedException` ，其他异常会继续抛出。比如需要身份认证时将请求重定向到相应的认证页面，当认证失败或者权限不足时返回相应的提示信息

#### Spring Security 自定义用户认证

**自定义认证过程**

实现 Spring Security 提供的 `UserDetailsService` 接口，并将该组件放入容器中就能自动生效，该接口只有一个抽象方法`loadUserByUsername`，源码如下：

```java
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

`loadUserByUsername`方法返回值为 `UserDetails` 对象，该对象也是一个接口，包含一些描述用户信息的方法，源码如下：

```java
public interface UserDetails extends Serializable {
	// 获取用户包含的权限集合，权限是一个继承了 `GrantedAuthority` 的对象
    Collection<? extends GrantedAuthority> getAuthorities();
	// 获取密码
    String getPassword();
	// 获取用户名
    String getUsername();
	// 判断账户是否未过期
    boolean isAccountNonExpired();
	// 判断账户是否未锁定
    boolean isAccountNonLocked();
	// 判断用户凭证是否没过期，即密码是否未过期
    boolean isCredentialsNonExpired();
	// 判断用户是否可用
    boolean isEnabled();
}
```

**自定义认证成功 or 认证失败逻辑**

实现 `AuthenticationFailureHandler` 或 `AuthenticationSuccessHandler`，并在 Spring Security 配置类进行配置：

```java
/** 安全配置 */
@Override
protected void configure(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
            .formLogin() // 表单登录
            // http.httpBasic() // HTTP Basic
            .loginProcessingUrl("/login") // 处理表单登录 URL
            .successHandler(authenticationSuccessHandler)
            .failureHandler(authenticationFailureHandler) // 认证失败处理
            .and()
            .authorizeRequests() // 授权配置
            .anyRequest()  // 所有请求
            .authenticated() // 都需要认证
            .and().csrf().disable(); // csrf禁用
}
```

#### Spring Security 短信验证码登录

Spring Security 默认只提供了账号密码的登录认证逻辑，手机短信验证码登录认证功能需要自行实现，可以模仿 Spring Security 账号密码登录逻辑代码来实现

#### Spring Security 权限控制

Spring Security 权限控制可以配合授权注解使用，具体注解参考[Spring-Security保护方法](https://mrbird.cc/Spring-Security保护方法.html)，要开启这些注解，需要在 Spring Security 配置文件中添加如下配置：

```java
// @EnableGlobalMethodSecurity(prePostEnabled = true) 开启全局方法安全校验注解
// 使用表达式时间方法级别的安全性4个注解可用
// @PreAuthorize 在方法调用之前, 基于表达式的计算结果来限制对方法的访问
// @PostAuthorize 允许方法调用, 但是如果表达式计算结果为false, 将抛出一个安全性异常
// @PostFilter 允许方法调用, 但必须按照表达式来过滤方法的结果
// @PreFilter 允许方法调用, 但必须在进入方法之前过滤输入值
@EnableWebSecurity  //注解开启 Spring Security 功能
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
}
```

#### OAuth2 四种授权模式

**一、授权码模式**

授权码模式是最能体现OAuth2协议，最严格，流程最完整的授权模式，流程如下所示：

![image-20190624150726.png](https://github.com/Cola-Ice/Spring-Security-OAuth2-Demo/raw/master/doc/image/image-20190624150726.png)

A. 客户端将用户导向认证服务器；

B. 用户决定是否给客户端授权；

C. 同意授权后，认证服务器将用户导向客户端提供的URL，并附上授权码；

D. 客户端通过重定向URL和授权码到认证服务器换取令牌；

E. 校验无误后发放令牌。

其中A步骤，客户端申请认证的URI，包含以下参数：

1. response_type：表示授权类型，必选项，此处的值固定为”code”，标识授权码模式
2. client_id：表示客户端的ID，必选项
3. redirect_uri：表示重定向URI，可选项
4. scope：表示申请的权限范围，可选项
5. state：表示客户端的当前状态，可以指定任意值，认证服务器会原封不动地返回这个值。

D步骤中，客户端向认证服务器申请令牌的HTTP请求，包含以下参数：

1. grant_type：表示使用的授权模式，必选项，此处的值固定为”authorization_code”。
2. code：表示上一步获得的授权码，必选项。
3. redirect_uri：表示重定向URI，必选项，且必须与A步骤中的该参数值保持一致。
4. client_id：表示客户端ID，必选项。

**二、密码模式**

在密码模式中，用户向客户端提供用户名密码，客户端通过用户名密码到认证服务器获取令牌。流程如下所示：

![image-20190624150726.png](https://github.com/Cola-Ice/Spring-Security-OAuth2-Demo/raw/master/doc/image/image-20190624150632.png)

A. 用户向客户端提供用户名和密码；

B. 客户端向认证服务器换取令牌；

C. 发放令牌。

B步骤中，客户端发出的HTTP请求，包含以下参数：

1. grant_type：表示授权类型，此处的值固定为”password”，必选项。
2. username：表示用户名，必选项。
3. password：表示用户的密码，必选项。
4. scope：表示权限范围，可选项。

剩下两种授权模式可以参考下面的参考链接，这里就不介绍了。

#### Spring Security OAuth2 入门

pom依赖

```pom
<dependency>
	<groupId>org.springframework.cloud</groupId>
	<artifactId>spring-cloud-starter</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.cloud</groupId>
	<artifactId>spring-cloud-starter-oauth2</artifactId>
</dependency>
```

##### 1.配置认证服务器

创建认证服务器很简单，只需要再 Spring Security 的配置类上使用 `@EnableAuthorizationServer` 注解标注即可，配置文件中指定client相关配置

```
security:
  oauth2:
    client:
      client-id: 5b12316f-4e51-43b3-b689-e7085912a7bc # client-id、client-secret没有配置会在启动时自动生成
      client-secret: a3e6b8ce-a44a-438a-89fe-0c3c2b8bab5c
      registered-redirect-uri: http://yarda.top # 没有配置时，授权会报 invalid request
```

##### 2.授权码模式获取令牌

启动项目，浏览器访问http://localhost:8080/oauth/authorize?response_type=code&client_id=5b12316f-4e51-43b3-b689-e7085912a7bc&redirect_uri=http://yarda.top&scope=all&state=hello

按照提示授权成功后，会携带授权码自动跳转到 redirect-uri 配置的地址

使用 postman，根据上面拿到的授权码获取 token，需要注意的是一个授权码只能使用一次

![image-20220112154335255](https://github.com/Cola-Ice/Spring-Security-OAuth2-Demo/raw/master/doc/image/image-20220112154335255.png)

##### 3.密码模式获取令牌

密码模式直接使用用户名密码，访问 `oauth/token` 接口获取 token

![image-20220112154315239](https://github.com/Cola-Ice/Spring-Security-OAuth2-Demo/raw/master/doc/image/image-20220112154315239.png)

##### 4.配置资源服务器

为什么需要配置资源服务器，没配置之前我们使用上边获取的token访问资源：

![image-20220112155349686](https://github.com/Cola-Ice/Spring-Security-OAuth2-Demo/raw/master/doc/image/image-20220112155349686.png)

```java
@Configuration
@EnableResourceServer //开启 Spring cloud oauth2 资源服务功能
public class ResourceServerConfig {
}
```

#### Spring Security OAuth2 自定义 Token 获取方式

Spring Security OAuth2 默认封装了授权码和密码模式，这里我们自定义通过用户名密码和手机短信验证码得方式来获取令牌

自定义 token 获取方式的关键是，如何再登陆成功处理器里返回 token。Spring Security OAuth2 默认的授权模式中，令牌的生成步骤如下：

![image-20190624150726.png](https://github.com/Cola-Ice/Spring-Security-OAuth2-Demo/raw/master/doc/image/image-20190624223930.png)

##### 1.自定义用户名密码方式获取令牌

先在资源服务器中加入以下配置：

```java
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
```

参考默认实现自定义 AuthenticationSuccessHandler，在该类里实现 token 返回逻辑

##### 2.短信验证码获取令牌

结合 Spring Security 短信验证码登录实现