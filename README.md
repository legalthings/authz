# Legalthings Authz

[![Build Status](https://travis-ci.org/legalthings/authz.svg?branch=master)](https://travis-ci.org/legalthings/authz)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/legalthings/authz/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/legalthings/authz/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/legalthings/authz/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/legalthings/authz/?branch=master)

Authorization and access control through [permission matching](https://github.com/legalthings/permission-matcher).


## Installation

```
composer require legalthings/authz
```


## Usage

```php
$authz = new LegalThings\Authz($_SESSION);

if (!$authz->is('user')) {
    echo "not logged in";
    return;
}

$user = $authz->getUser();

$document = loadDocument();

if (!$authz->may('read', $document)) {
    echo "not allowed to read";
    return;
}

echo $document->contents;
```

### Session

This library expects a session to have either a 'user' or a 'party' property. A party is an unregistered user.

For both a user and party, the `email` property is automatically used as group. In addition a user should have an
`authz_groups` property.

```php
$session = [
    'user' => [
        'id' => '1234',
        'email' => 'john@example.com',
        'authz_groups' => [
            'user',
            '/users/1234',
            '/organizations/abcdef'
        ]
    ]
];
```

By default `Authz::getUser()` will return a `LegalThings\Autz\User` object. However you can user your own the user
factory through the constructor to use a different class as long as it implements `LegalThings\Authz\UserInterface`.
Your own class may use different properties for the user than as described here.

### Permissions

The [permission matcher](https://github.com/legalthings/permission-matcher) expects the following format for the
permissions:

```
$permissions = [
    'read' => ['/organizations/abcdef', 'admin'],
    'write' => ['/teams/5555666', 'admin']
];
```

Rather that an array with permissions, you can also an object on which the permission apply to `Authz::may()`. That
object must implement `LegalThings\Authz\SubjectInterface`.
