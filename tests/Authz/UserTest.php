<?php

namespace LegalThings\Authz;

use LegalThings\Authz\User;

/**
 * @covers LegalThings\Authz\User
 */
class UserTest extends \PHPUnit\Framework\TestCase
{
    public function testGetGroupsWithNothing()
    {
        $user = new User();
        
        $this->assertEquals([], $user->getGroups());
    }
    
    public function testGetGroupsWithEmail()
    {
        $user = new User();
        $user->email = 'john@example.com';
        
        $this->assertEquals(['john@example.com'], $user->getGroups());
    }
    
    public function testGetGroupsWithAuthzGroups()
    {
        $user = new User();
        $user->authz_groups = [
            '/users/12345',
            'users'
        ];
        
        $this->assertEquals(['/users/12345', 'users'], $user->getGroups());
    }
    
    public function testFromData()
    {
        $user = User::fromData([
            'id' => '12345',
            'email' => 'john@example.com',
            'name' => 'John Doe'
        ]);
        
        $this->assertInstanceOf(User::class, $user);
        $this->assertAttributeEquals('12345', 'id', $user);
        $this->assertAttributeEquals('john@example.com', 'email', $user);
        $this->assertAttributeEquals('John Doe', 'name', $user);
    }
}
