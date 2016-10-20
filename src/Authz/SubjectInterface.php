<?php

namespace LegalThings\Authz;

/**
 * Interface for objects that are subjected to access control
 */
interface SubjectInterface
{
    /**
     * Get a list of permissions with authz groups
     * 
     * @return array
     */
    public function getPermissions();
}
