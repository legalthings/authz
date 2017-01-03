<?php

namespace LegalThings\Authz;

use LegalThings\Authz;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Use Authz as Middleware.
 * 
 * Will use the `authz` request attribute OR the `authz` property of the `route` request attribute.
 */
class Middleware
{
    /**
     * @var Authz
     */
    protected $authz;
    
    /**
     * Response status or callback for when session is without a user
     * @var int|callable
     */
    protected $responseNoUser = 401;
    
    /**
     * Response status or callback for when user isn't in specified group
     * @var int|callable
     */
    protected $responseForbidden = 403;
    
    
    /**
     * Class constructor
     * 
     * @param Authz        $authz
     * @param int|callable $noUser     Response status or callback for when session is without a user
     * @param int|callable $forbidden  Response status or callback for when user isn't in specified group
     */
    public function __construct(Authz $authz, $noUser = 401, $forbidden = 403)
    {
        if (!is_int($noUser) && !ctype_digit($noUser) && !is_callable($noUser)) {
            throw new \InvalidArgumentException('noUser argument should be an integer or callable');
        }
        
        if (!is_int($forbidden) && !ctype_digit($forbidden) && !is_callable($forbidden)) {
            throw new \InvalidArgumentException('forbidden argument should be an integer or callable');
        }
        
        $this->authz = $authz;
        
        $this->responseNoUser = $noUser;
        $this->responseForbidden = $forbidden;
    }

    
    /**
     * Determine the required authz group for the request
     * 
     * @param ServerRequestInterface $request
     * @return string|null
     */
    protected function getGroup(ServerRequestInterface $request)
    {
        $group = $request->getAttribute('authz');
        
        if (!isset($group)) {
            $route = $request->getAttribute('route');
        }
        
        if (isset($route)) {
            if (is_array($route)) {
                $route = (object)$route;
            }
            
            $group = isset($route->authz) ? $route->authz : (isset($route->auth) ? $route->auth : null);
        }
        
        return $group;
    }
    
    
    /**
     * Set response to access denied
     * 
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     * @return RequestInterface
     */
    protected function accessDenied(ServerRequestInterface $request, ResponseInterface $response)
    {
        $status = !$this->authz->getUser() ? $this->responseNoUser : $this->responseForbidden;

        if (is_callable($status)) {
            $forbidden = $status($request, $response);
        } else {
            $forbidden = $response->withStatus($status);
            $forbidden->getBody()->write('access denied');
        }

        return $forbidden;
    }
    
    /**
     * Invoke middleware
     * 
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     * @param callable               $next
     * @return RequestInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, $next)
    {
        if (!is_callable($next)) {
            throw new \InvalidArgumentException("next method should be a callback");
        }
        
        $group = $this->getGroup($request);
        
        if (!isset($group) && !$this->authz->is($group)) {
            return $this->accessDenied($request, $response);
        }
        
        return $next($request, $response);
    }
}

