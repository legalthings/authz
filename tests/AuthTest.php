<?php

namespace LegalThings;

use LegalThings\Auth\User;
use LegalThings\PermissionMatcher;

/**
 * @covers LegalThings\Auth
 */
class AuthTest extends \PHPUnit\Framework\TestCase
{
    public function testGetSession()
    {
        $auth = new Auth(['id' => 'eksdfiue']);
        $session = $auth->getSession();
        
        $this->assertInternalType('array', $session);
        $this->assertArrayHasKey('id', $session);
        $this->assertEquals('eksdfiue', $session['id']);
    }
    
    public function testGetUserWithNoSession()
    {
        $auth = new Auth([]);
        $this->assertNull($auth->getUser());
    }
    
    public function testGetUserWithUser()
    {
        $auth = new Auth([
            'user' => [
                'id' => '12345',
                'email' => 'john@example.com',
                'authz_groups' => [
                    'users',
                    '/users/12345',
                    '/organizations/889900/users'
                ]
            ]
        ]);
        
        $user = $auth->getUser();
        
        $this->assertInstanceOf(User::class, $user);
        $this->assertAttributeEquals('12345', 'id', $user);
        $this->assertAttributeEquals('john@example.com', 'email', $user);
        $this->assertAttributeEquals([
            'users',
            '/users/12345',
            '/organizations/889900/users'
        ], 'authz_groups', $user);
    }
    
    public function testGetUserWithParty()
    {
        $auth = new Auth([
            'party' => [
                'email' => 'john@example.com'
            ]
        ]);
        
        $user = $auth->getUser();
        
        $this->assertInstanceOf(User::class, $user);
        $this->assertAttributeEquals('john@example.com', 'email', $user);
    }
    
    
    public function testCanWithoutUser()
    {
        $permissions = ['read' => ['users'], 'write' => ['/organizations/889900/users'], 'full' => 'admin'];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(4))->method('match')
            ->with($permissions, [])
            ->willReturn([]);
        
        $auth = new Auth([], $permissionMatcher);
        
        $this->assertFalse($auth->can('read', $permissions));
        $this->assertFalse($auth->can('write', $permissions));
        $this->assertFalse($auth->can('full', $permissions));
        $this->assertFalse($auth->can(['write', 'full'], $permissions));
    }
    
    public function testCanWithUser()
    {
        $permissions = ['read' => ['users'], 'write' => ['/organizations/889900/users'], 'full' => 'admin'];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(4))->method('match')
            ->with($permissions, ['users'])
            ->willReturn(['read']);
        
        $auth = new Auth([
            'user' => [
                'authz_groups' => [
                    'users'
                ]
            ]
        ], $permissionMatcher);
        
        $this->assertTrue($auth->can('read', $permissions));
        $this->assertFalse($auth->can('write', $permissions));
        $this->assertFalse($auth->can('full', $permissions));
        $this->assertFalse($auth->can(['write', 'full'], $permissions));
    }
    
    public function testCanWithOrganizationUser()
    {
        $permissions = ['read' => ['users'], 'write' => ['/organizations/889900/users'], 'full' => 'admin'];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(4))->method('match')
            ->with($permissions, ['users', '/organizations/889900/users'])
            ->willReturn(['read', 'write']);
        
        $auth = new Auth([
            'user' => [
                'authz_groups' => [
                    'users',
                    '/organizations/889900/users'
                ]
            ]
        ], $permissionMatcher);
        
        $this->assertTrue($auth->can('read', $permissions));
        $this->assertTrue($auth->can('write', $permissions));
        $this->assertFalse($auth->can('full', $permissions));
        $this->assertTrue($auth->can(['write', 'full'], $permissions));
    }
    
    public function testCanWithAdmin()
    {
        $permissions = ['read' => ['users'], 'write' => ['/organizations/889900/users'], 'full' => 'admin'];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(4))->method('match')
            ->with($permissions, ['admin'])
            ->willReturn(['full']);
        
        $auth = new Auth([
            'user' => [
                'authz_groups' => [
                    'admin'
                ]
            ]
        ], $permissionMatcher);
        
        $this->assertFalse($auth->can('read', $permissions));
        $this->assertFalse($auth->can('write', $permissions));
        $this->assertTrue($auth->can('full', $permissions));
        $this->assertTrue($auth->can(['write', 'full'], $permissions));
    }
    
    public function testCanWithParty()
    {
        $permissions = ['read' => ['users', 'john@example.com'], 'write' => ['/organizations/889900/users']];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(2))->method('match')
            ->with($permissions, ['john@example.com'])
            ->willReturn(['read']);
        
        $auth = new Auth([
            'party' => [
                'email' => 'john@example.com'
            ]
        ], $permissionMatcher);
        
        $this->assertTrue($auth->can('read', $permissions));
        $this->assertFalse($auth->can('write', $permissions));
    }
}
