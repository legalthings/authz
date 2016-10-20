<?php

namespace LegalThings\Authz;

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
