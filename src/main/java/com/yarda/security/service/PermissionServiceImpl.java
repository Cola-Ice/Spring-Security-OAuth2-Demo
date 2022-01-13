package com.yarda.security.service;

import org.springframework.stereotype.Service;

/**
 * 权限验证 service
 * @author xuezheng
 * @date 2022/1/6 19:01
 * @version 1.0
 */
@Service("ss")
public class PermissionServiceImpl {

    /**
     * 是否拥有某个功能权限
     * @param perm 权限点
     * @return true or false
     */
    public boolean hasPermission(String perm){
        System.out.println("权限控制："+ perm);
        return true;
    }
}
