package com.github.zhangkaitao.shiro.chapter3;

import junit.framework.Assert;
import org.apache.shiro.authz.UnauthorizedException;
import org.junit.Test;

import java.util.Arrays;

/**
 * 基于角色的权限控制
 * QT Shiro提供的授权的方式只有代码、注解、前端，也是一种写死角色的方法，如何做到角色和权限更动态化？
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-26
 * <p>Version: 1.0
 */
public class RoleTest extends BaseTest {

	/**
	 * 校验是否具备某个角色
	 */
    @Test
    public void testHasRole() {
        login("classpath:shiro-role.ini", "zhang", "123");
        //判断拥有角色：role1
        Assert.assertTrue(subject().hasRole("role1"));
        //判断拥有角色：role1 and role2
        Assert.assertTrue(subject().hasAllRoles(Arrays.asList("role1", "role2")));
        //判断拥有角色：role1 and role2 and !role3
        boolean[] result = subject().hasRoles(Arrays.asList("role1", "role2", "role3"));
        Assert.assertEquals(true, result[0]);
        Assert.assertEquals(true, result[1]);
        Assert.assertEquals(false, result[2]);
    }

    @Test(expected = UnauthorizedException.class)
    public void testCheckRole() {
        login("classpath:shiro-role.ini", "zhang", "123");
        //断言拥有角色：role1
        subject().checkRole("role1");
        //断言拥有角色：role1 and role3 失败抛出异常
        subject().checkRoles("role1", "role3");
    }

}
