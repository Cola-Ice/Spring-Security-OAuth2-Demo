package com.yarda.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 测试 controller
 * @author xuezheng
 * @date 2022/1/6 19:01
 * @version 1.0
 */
@RestController("aa")
public class TestController {

    @PreAuthorize("@ss.hasPermission('hello')")
    @GetMapping("/hello")
    public String hello(){
        return "hello security";
    }
}
