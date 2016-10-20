<?php

namespace LegalThings;

use LegalThings\Auth\User;
use LegalThings\Auth\UserInterface;
use LegalThings\Auth\SubjectInterface;
use LegalThings\PermissionMatcher;

/**
 * Authorization and access control
 */
class Auth
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
        
        return (boolean)$this->matcher->match([1 => $group], $groups);
    }
    
    /**
     * Check if user has a privilege
     * 
     * @param string|string[]        $privilege
     * @param array|SubjectInterface $permissions
     * @return boolean
     */
    public function can($privilege, $permissions)
    {
        if (!is_array($permissions) && !$permissions instanceof SubjectInterface) {
            throw new \InvalidArgumentException("permissions should be an array or SubjectInterface");
        }
        
        $user = $this->getUser();
        $groups = $user ? $user->getGroups() : [];
        
        if ($permissions instanceof SubjectInterface) {
            $permissions = $permissions->getPermissions();
        }
        
        $privileges = $this->matcher->match($permissions, $groups);
        
        return array_intersect((array)$privilege, $privileges) !== [];
    }
}
