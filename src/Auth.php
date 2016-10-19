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
     * @var PermissionMatcher
     */
    protected $matcher;
    
    /**
     * Class constructor
     * 
     * @param array             $session
     * @param PermissionMatcher $matcher
     */
    public function __construct(array $session, PermissionMatcher $matcher = null)
    {
        $this->session = $session;
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
     * Get the session user
     * 
     * @return UserInterface
     */
    public function getUser()
    {
        if (isset($this->session['user'])) {
            $data = $this->session['user'];
        } elseif (isset($this->session['party'])) {
            $data = $this->session['party'];
        }
        
        return isset($data) ? User::fromData($data) : null;
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
