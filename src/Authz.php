<?php

namespace LegalThings;

use LegalThings\Authz\User;
use LegalThings\Authz\UserInterface;
use LegalThings\Authz\SubjectInterface;
use LegalThings\Authz\Middleware;
use LegalThings\PermissionMatcher;

/**
 * Authorization and access control
 */
class Authz
{
    /**
     * @var array
     */
    protected $session;
    
    /**
     * Factory method to create a new user
     * @var string 
     */
    protected $userFactory;
    
    /**
     * @var UserInterface
     */
    protected $user;
    
    /**
     * @var PermissionMatcher
     */
    protected $matcher;
    
    
    /**
     * Class constructor
     * 
     * @param array             $session
     * @param callable          $userFactory
     * @param PermissionMatcher $matcher
     */
    public function __construct(array $session, $userFactory = null, PermissionMatcher $matcher = null)
    {
        if (isset($userFactory) && !is_callable($userFactory)) {
            throw new \InvalidArgumentException("User factory should be callable");
        }
        
        $this->session = $session;
        $this->userFactory = $userFactory ?: [$this, 'createUser'];
        $this->matcher = $matcher ?: new PermissionMatcher();
    }
    
    /**
     * Get the session
     * 
     * @return array
     */
    public function getSession()
    {
        return $this->session;
    }

    
    /**
     * Default user factory method
     * 
     * @param string $type  'user' or 'party'
     * @param array  $data
     * @return User
     */
    protected function createUser($type, $data)
    {
        if ($type === 'party') {
            unset($data['id'], $data['authz_groups']);
        }
        
        return User::fromData($data);
    }

    /**
     * Initialize user
     */
    protected function initUser()
    {
        $factory = $this->userFactory;
        
        if (isset($this->session['user'])) {
            $this->user = $factory('user', $this->session['user']);
        } elseif (isset($this->session['party'])) {
            $this->user = $factory('party', $this->session['party']);
        } else {
            $this->user = false;
        }
    }
    
    /**
     * Get the session user
     * 
     * @return UserInterface
     */
    public function getUser()
    {
        if (!isset($this->user)) {
            $this->initUser();
        }
        
        return $this->user ?: null;
    }
    
    
    /**
     * Check if the user is in a specific group
     * 
     * @param string $group
     * @return boolean
     */
    public function is($group)
    {
        $user = $this->getUser();
        $groups = $user ? $user->getGroups() : [];
        
        return (boolean)$this->matcher->match([$group => 1], $groups);
    }
    
    /**
     * Check if user has a privilege
     * 
     * @param string|string[]        $privilege
     * @param array|SubjectInterface $permissions
     * @return boolean
     */
    public function may($privilege, $permissions)
    {
        if (!is_array($permissions) && !$permissions instanceof SubjectInterface) {
            throw new \InvalidArgumentException("Permissions should be an array or SubjectInterface");
        }
        
        $user = $this->getUser();
        $groups = $user ? $user->getGroups() : [];
        
        if ($permissions instanceof SubjectInterface) {
            $permissions = $permissions->getPermissions();
        }
        
        $privileges = $this->matcher->match($permissions, $groups);
        
        return array_intersect((array)$privilege, $privileges) !== [];
    }
    
    /**
     * Get middleware for the authz object
     * 
     * @param int|callable $noUser     Response status or callback for when session is without a user
     * @param int|callable $forbidden  Response status or callback for when user isn't in specified group
     * @return Middleware
     */    
    public function asMiddleware($noUser = 401, $forbidden = 403)
    {
        return new Middleware($this, $noUser, $forbidden);
    }
}
