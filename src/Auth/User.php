<?php

namespace LegalThings\Auth;

use LegalThings\Auth\UserInterface;

/**
 * Basic implementation of a user
 */
class User extends \stdClass implements UserInterface
{
    /**
     * Get all authorization groups
     * 
     * @return array
     */
    public function getGroups()
    {
        $groups = isset($this->authz_groups) ? $this->authz_groups : [];
        
        if (isset($this->email)) {
            $groups[] = $this->email;
        }
        
        return $groups;
    }
    
    /**
     * Factory method 
     * 
     * @param array $data
     * @return self
     */
    public static function fromData($data)
    {
        $user = new User();
        
        foreach ($data as $key => $value) {
            $user->$key = $value;
        }
        
        return $user;
    }
}
