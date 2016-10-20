<?php

namespace LegalThings;

use LegalThings\Authz\User;
use LegalThings\Authz\UserInterface;
use LegalThings\Authz\SubjectInterface;
use LegalThings\PermissionMatcher;

/**
 * @covers LegalThings\Authz
 */
class AuthzTest extends \PHPUnit\Framework\TestCase
{
    public function testGetSession()
    {
        $auth = new Authz(['id' => 'eksdfiue']);
        $session = $auth->getSession();
        
        $this->assertInternalType('array', $session);
        $this->assertArrayHasKey('id', $session);
        $this->assertEquals('eksdfiue', $session['id']);
    }
    
    
    public function testGetUserWithNoSession()
    {
        $auth = new Authz([]);
        $this->assertNull($auth->getUser());
    }
    
    public function testGetUserWithUser()
    {
        $auth = new Authz([
            'user' => [
                'id' => '12345',
                'email' => 'john@example.com',
                'authz_groups' => [
                    'user',
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
            'user',
            '/users/12345',
            '/organizations/889900/users'
        ], 'authz_groups', $user);
    }
    
    public function testGetUserWithParty()
    {
        $auth = new Authz([
            'party' => [
                'email' => 'john@example.com'
            ]
        ]);
        
        $user = $auth->getUser();
        
        $this->assertInstanceOf(User::class, $user);
        $this->assertAttributeEquals('john@example.com', 'email', $user);
    }
    
    
    public function testIsWithoutUser()
    {
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->once())->method('match')
            ->with([1 => 'user'], [])
            ->willReturn([]);
        
        $auth = new Authz([], null, $permissionMatcher);
        
        $this->assertFalse($auth->is('user'));
    }
    
    public function testIsWithUser()
    {
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(2))->method('match')
            ->withConsecutive([[1 => 'user'], ['user']], [[1 => 'admin'], ['user']])
            ->willReturnOnConsecutiveCalls(1, null);
        
        $auth = new Authz([
            'user' => [
                'authz_groups' => [
                    'user'
                ]
            ]
        ], null, $permissionMatcher);
        
        $this->assertTrue($auth->is('user'));
        $this->assertFalse($auth->is('admin'));
    }
    
    
    public function testMayWithoutUser()
    {
        $permissions = ['user' => ['read'], '/organizations/889900/users' => ['write'], 'admin' => ['full']];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(4))->method('match')
            ->with($permissions, [])
            ->willReturn([]);
        
        $auth = new Authz([], null, $permissionMatcher);
        
        $this->assertFalse($auth->may('read', $permissions));
        $this->assertFalse($auth->may('write', $permissions));
        $this->assertFalse($auth->may('full', $permissions));
        $this->assertFalse($auth->may(['write', 'full'], $permissions));
    }
    
    public function testMayWithUser()
    {
        $permissions = ['user' => ['read'], '/organizations/889900/users' => ['write'], 'admin' => ['full']];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(4))->method('match')
            ->with($permissions, ['user'])
            ->willReturn(['read']);
        
        $auth = new Authz([
            'user' => [
                'authz_groups' => [
                    'user'
                ]
            ]
        ], null, $permissionMatcher);
        
        $this->assertTrue($auth->may('read', $permissions));
        $this->assertFalse($auth->may('write', $permissions));
        $this->assertFalse($auth->may('full', $permissions));
        $this->assertFalse($auth->may(['write', 'full'], $permissions));
    }
    
    public function testMayWithOrganizationUser()
    {
        $permissions = ['user' => ['read'], '/organizations/889900/users' => ['write'], 'admin' => ['full']];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(4))->method('match')
            ->with($permissions, ['user', '/organizations/889900/users'])
            ->willReturn(['read', 'write']);
        
        $auth = new Authz([
            'user' => [
                'authz_groups' => [
                    'user',
                    '/organizations/889900/users'
                ]
            ]
        ], null, $permissionMatcher);
        
        $this->assertTrue($auth->may('read', $permissions));
        $this->assertTrue($auth->may('write', $permissions));
        $this->assertFalse($auth->may('full', $permissions));
        $this->assertTrue($auth->may(['write', 'full'], $permissions));
    }
    
    public function testMayWithAdmin()
    {
        $permissions = ['user' => ['read'], '/organizations/889900/users' => ['write'], 'admin' => ['full']];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(4))->method('match')
            ->with($permissions, ['admin'])
            ->willReturn(['full']);
        
        $auth = new Authz([
            'user' => [
                'authz_groups' => [
                    'admin'
                ]
            ]
        ], null, $permissionMatcher);
        
        $this->assertFalse($auth->may('read', $permissions));
        $this->assertFalse($auth->may('write', $permissions));
        $this->assertTrue($auth->may('full', $permissions));
        $this->assertTrue($auth->may(['write', 'full'], $permissions));
    }
    
    public function testMayWithParty()
    {
        $permissions = ['user' => ['read'], 'john@example.com' => ['read'], '/organizations/889900/users' => ['write']];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(2))->method('match')
            ->with($permissions, ['john@example.com'])
            ->willReturn(['read']);
        
        $auth = new Authz([
            'party' => [
                'email' => 'john@example.com'
            ]
        ], null, $permissionMatcher);
        
        $this->assertTrue($auth->may('read', $permissions));
        $this->assertFalse($auth->may('write', $permissions));
    }
    
    public function testMayWithSubject()
    {
        $permissions = ['user' => ['read'], '/organizations/889900/users' => ['write'], 'admin' => ['full']];
        
        $subject = $this->createMock(SubjectInterface::class);
        $subject->expects($this->once())->method('getPermissions')
            ->willReturn($permissions);
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->once())->method('match')
            ->with($permissions, [])
            ->willReturn([]);
        
        $auth = new Authz([], null, $permissionMatcher);
        
        $this->assertFalse($auth->may('read', $subject));
    }    
    
    /**
     * @expectedException \InvalidArgumentException
     */
    public function testMayWithInvalidSubject()
    {
        $subject = $this->getMockBuilder(\stdClass::class)->setMethods(['getPermissions'])->getMock();
        $subject->expects($this->never())->method('getPermissions');
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->never())->method('match');
        
        $auth = new Authz([], null, $permissionMatcher);
        
        $auth->may('read', $subject);
    }    
    
    
    public function testUserFactoryWithoutUser()
    {
        $userMock = $this->createMock(UserInterface::class);
        $userData = ['id' => '12345', 'email' => 'john@example.com'];
        
        $factory = $this->getMockBuilder(\stdClass::class)->setMethods(['__invoke'])->getMock();
        $factory->expects($this->once())->method('__invoke')
            ->with('user', $userData)
            ->willReturn($userMock);
        
        $auth = new Authz(['user' => $userData], $factory);
        
        $this->assertSame($userMock, $auth->getUser());
        
        // Shouldn't call fatory
        $this->assertSame($userMock, $auth->getUser());
    }
    
    public function testUserFactoryWithUser()
    {
        $userMock = $this->createMock(UserInterface::class);
        $userData = ['id' => '12345', 'email' => 'john@example.com'];
        
        $factory = $this->getMockBuilder(\stdClass::class)->setMethods(['__invoke'])->getMock();
        $factory->expects($this->once())->method('__invoke')
            ->with('user', $userData)
            ->willReturn($userMock);
        
        $auth = new Authz(['user' => $userData], $factory);
        
        $this->assertSame($userMock, $auth->getUser());
        
        // Shouldn't call fatory
        $this->assertSame($userMock, $auth->getUser());
    }
    
    public function testUserFactoryWithParty()
    {
        $userMock = $this->createMock(UserInterface::class);
        $userData = ['email' => 'john@example.com'];
        
        $factory = $this->getMockBuilder(\stdClass::class)->setMethods(['__invoke'])->getMock();
        $factory->expects($this->once())->method('__invoke')
            ->with('party', $userData)
            ->willReturn($userMock);
        
        $auth = new Authz(['party' => $userData], $factory);
        
        $this->assertSame($userMock, $auth->getUser());
        
        // Shouldn't call factory
        $this->assertSame($userMock, $auth->getUser());
    }
    
    /**
     * @expectedException \InvalidArgumentException
     */
    public function testInvalidUserFactory()
    {
        new Authz([], 'foo bar zoo');
    }
}
