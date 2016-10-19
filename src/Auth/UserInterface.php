<?php

namespace LegalThings\Auth;

/**
 * User interface
 */
interface UserInterface
{
    /**
     * Get the authorization groups
     * 
     * @return array
     */
    public function getGroups();
}
