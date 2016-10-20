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
    protected function assertPrivatePropertySame($expected, $property, $object)
    {
        $this->assertInternalType('object', $object);
        
        $refl = new \ReflectionProperty($property[0], $property[1]);
        
        $refl->setAccessible(true);
        $this->assertSame($expected, $refl->getValue($object));
    }
    
    
    public function testGetSession()
    {
        $authz = new Authz(['id' => 'eksdfiue']);
        $session = $authz->getSession();
        
        $this->assertInternalType('array', $session);
        $this->assertArrayHasKey('id', $session);
        $this->assertEquals('eksdfiue', $session['id']);
    }
    
    
    public function testGetUserWithNoSession()
    {
        $authz = new Authz([]);
        $this->assertNull($authz->getUser());
    }
    
    public function testGetUserWithUser()
    {
        $authz = new Authz([
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
        
        $user = $authz->getUser();
        
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
        $authz = new Authz([
            'party' => [
                'email' => 'john@example.com'
            ]
        ]);
        
        $user = $authz->getUser();
        
        $this->assertInstanceOf(User::class, $user);
        $this->assertAttributeEquals('john@example.com', 'email', $user);
    }
    
    
    public function testIsWithoutUser()
    {
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->once())->method('match')
            ->with(['user' =>  1], [])
            ->willReturn([]);
        
        $authz = new Authz([], null, $permissionMatcher);
        
        $this->assertFalse($authz->is('user'));
    }
    
    public function testIsWithUser()
    {
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(2))->method('match')
            ->withConsecutive(
                [['user' => 1], ['user', 'john@example.com']],
                [['admin' => 1], ['user', 'john@example.com']]
            )
            ->willReturnOnConsecutiveCalls([1], []);
        
        $authz = new Authz([
            'user' => [
                'email' => 'john@example.com',
                'authz_groups' => [
                    'user'
                ]
            ]
        ], null, $permissionMatcher);
        
        $this->assertTrue($authz->is('user'));
        $this->assertFalse($authz->is('admin'));
    }
    
    public function testIsWithParty()
    {
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->once())->method('match')
            ->with(['user' => 1], ['john@example.com'])
            ->willReturn([]);
        
        $authz = new Authz([
            'party' => [
                'email' => 'john@example.com',
                'authz_groups' => [
                    'user' // ignored
                ]
            ]
        ], null, $permissionMatcher);
        
        $this->assertFalse($authz->is('user'));
    }
    
    
    public function testMayWithoutUser()
    {
        $permissions = ['user' => ['read'], '/organizations/889900/users' => ['write'], 'admin' => ['full']];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(4))->method('match')
            ->with($permissions, [])
            ->willReturn([]);
        
        $authz = new Authz([], null, $permissionMatcher);
        
        $this->assertFalse($authz->may('read', $permissions));
        $this->assertFalse($authz->may('write', $permissions));
        $this->assertFalse($authz->may('full', $permissions));
        $this->assertFalse($authz->may(['write', 'full'], $permissions));
    }
    
    public function testMayWithUser()
    {
        $permissions = ['user' => ['read'], '/organizations/889900/users' => ['write'], 'admin' => ['full']];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(4))->method('match')
            ->with($permissions, ['user'])
            ->willReturn(['read']);
        
        $authz = new Authz([
            'user' => [
                'authz_groups' => [
                    'user'
                ]
            ]
        ], null, $permissionMatcher);
        
        $this->assertTrue($authz->may('read', $permissions));
        $this->assertFalse($authz->may('write', $permissions));
        $this->assertFalse($authz->may('full', $permissions));
        $this->assertFalse($authz->may(['write', 'full'], $permissions));
    }
    
    public function testMayWithOrganizationUser()
    {
        $permissions = ['user' => ['read'], '/organizations/889900/users' => ['write'], 'admin' => ['full']];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(4))->method('match')
            ->with($permissions, ['user', '/organizations/889900/users'])
            ->willReturn(['read', 'write']);
        
        $authz = new Authz([
            'user' => [
                'authz_groups' => [
                    'user',
                    '/organizations/889900/users'
                ]
            ]
        ], null, $permissionMatcher);
        
        $this->assertTrue($authz->may('read', $permissions));
        $this->assertTrue($authz->may('write', $permissions));
        $this->assertFalse($authz->may('full', $permissions));
        $this->assertTrue($authz->may(['write', 'full'], $permissions));
    }
    
    public function testMayWithAdmin()
    {
        $permissions = ['user' => ['read'], '/organizations/889900/users' => ['write'], 'admin' => ['full']];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(4))->method('match')
            ->with($permissions, ['admin'])
            ->willReturn(['full']);
        
        $authz = new Authz([
            'user' => [
                'authz_groups' => [
                    'admin'
                ]
            ]
        ], null, $permissionMatcher);
        
        $this->assertFalse($authz->may('read', $permissions));
        $this->assertFalse($authz->may('write', $permissions));
        $this->assertTrue($authz->may('full', $permissions));
        $this->assertTrue($authz->may(['write', 'full'], $permissions));
    }
    
    public function testMayWithParty()
    {
        $permissions = ['user' => ['read'], 'john@example.com' => ['read'], '/organizations/889900/users' => ['write']];
        
        $permissionMatcher = $this->createMock(PermissionMatcher::class);
        $permissionMatcher->expects($this->exactly(2))->method('match')
            ->with($permissions, ['john@example.com'])
            ->willReturn(['read']);
        
        $authz = new Authz([
            'party' => [
                'email' => 'john@example.com'
            ]
        ], null, $permissionMatcher);
        
        $this->assertTrue($authz->may('read', $permissions));
        $this->assertFalse($authz->may('write', $permissions));
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
        
        $authz = new Authz([], null, $permissionMatcher);
        
        $this->assertFalse($authz->may('read', $subject));
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
        
        $authz = new Authz([], null, $permissionMatcher);
        
        $authz->may('read', $subject);
    }    
    
    
    public function testUserFactoryWithoutUser()
    {
        $userMock = $this->createMock(UserInterface::class);
        $userData = ['id' => '12345', 'email' => 'john@example.com'];
        
        $factory = $this->getMockBuilder(\stdClass::class)->setMethods(['__invoke'])->getMock();
        $factory->expects($this->once())->method('__invoke')
            ->with('user', $userData)
            ->willReturn($userMock);
        
        $authz = new Authz(['user' => $userData], $factory);
        
        $this->assertSame($userMock, $authz->getUser());
        
        // Shouldn't call fatory
        $this->assertSame($userMock, $authz->getUser());
    }
    
    public function testUserFactoryWithUser()
    {
        $userMock = $this->createMock(UserInterface::class);
        $userData = ['id' => '12345', 'email' => 'john@example.com'];
        
        $factory = $this->getMockBuilder(\stdClass::class)->setMethods(['__invoke'])->getMock();
        $factory->expects($this->once())->method('__invoke')
            ->with('user', $userData)
            ->willReturn($userMock);
        
        $authz = new Authz(['user' => $userData], $factory);
        
        $this->assertSame($userMock, $authz->getUser());
        
        // Shouldn't call fatory
        $this->assertSame($userMock, $authz->getUser());
    }
    
    public function testUserFactoryWithParty()
    {
        $userMock = $this->createMock(UserInterface::class);
        $userData = ['email' => 'john@example.com'];
        
        $factory = $this->getMockBuilder(\stdClass::class)->setMethods(['__invoke'])->getMock();
        $factory->expects($this->once())->method('__invoke')
            ->with('party', $userData)
            ->willReturn($userMock);
        
        $authz = new Authz(['party' => $userData], $factory);
        
        $this->assertSame($userMock, $authz->getUser());
        
        // Shouldn't call factory
        $this->assertSame($userMock, $authz->getUser());
    }
    
    /**
     * @expectedException \InvalidArgumentException
     */
    public function testInvalidUserFactory()
    {
        new Authz([], 'foo bar zoo');
    }
    
    
    public function testAsMiddleware()
    {
        $authz = new Authz([]);
        $middleware = $authz->asMiddleware(400, 402);
        
        $this->assertPrivatePropertySame($authz, [Authz\Middleware::class, 'authz'], $middleware);
        $this->assertPrivatePropertySame(400, [Authz\Middleware::class, 'responseNoUser'], $middleware);
        $this->assertPrivatePropertySame(402, [Authz\Middleware::class, 'responseForbidden'], $middleware);
    }
    
    
    /**
     * @group functional
     */
    public function testIsWithRealPermissionMatcher()
    {
        $authz = new Authz([
            'user' => [
                'authz_groups' => [
                    'user'
                ]
            ]
        ]);
        
        $this->assertTrue($authz->is('user'));
        $this->assertFalse($authz->is('admin'));
    }
    
    /**
     * @group functional
     */
    public function testMayWithRealPermissionMatcher()
    {
        $permissions = ['user' => ['read'], '/organizations/889900/users' => ['write']];
        
        $authz = new Authz([
            'user' => [
                'authz_groups' => [
                    'user'
                ]
            ]
        ]);
        
        $this->assertTrue($authz->may('read', $permissions));
        $this->assertFalse($authz->may('write', $permissions));
    }
}
