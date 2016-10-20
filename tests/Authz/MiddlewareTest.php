<?php

namespace LegalThings\Authz;

use LegalThings\Authz;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * @covers LegalThings\Authz\Middleware
 */
class MiddlewareTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var ResponseInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $response;
    
    public function setUp()
    {
        $this->response = $this->createMock(ResponseInterface::class);
    }
    
    /**
     * Create an Authz mock
     * 
     * @param string  $group
     * @param boolean $return
     * @param boolean $hasUser
     * @return Authz|\PHPUnit_Framework_MockObject_MockObject
     */
    protected function createAuthzMock($group, $return = true, $hasUser = false)
    {
        $authz = $this->createMock(Authz::class);
        
        if (isset($group)) {
            $authz->expects($this->once())->method('is')
                ->with($group)
                ->willReturn($return);
        } else {
            $authz->expects($this->never())->method('is');
        }
        
        $authz->expects($this->any())->method('getUser')
            ->willReturn($hasUser ? $this->createMock(Authz\UserInterface::class) : null);
        
        return $authz;
    }
    
    /**
     * Create mock for next callback
     * 
     * @param \PHPUnit_Framework_MockObject_Matcher_Invocation $matcher
     * @param mixed                                            $return    Return value
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    protected function createCallbackMock(\PHPUnit_Framework_MockObject_Matcher_Invocation $matcher, $return = null)
    {
        $callback = $this->getMockBuilder(\stdClass::class)->setMethods(['__invoke'])->getMock();
        $callback->expects($matcher)->method('__invoke')
            ->willReturn($return);
        
        return $callback;
    }
    
    /**
     * @return ResponseInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    protected function createForbiddenMock()
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->expects($this->once())->method('write')->with('access denied');
        
        $forbidden = $this->createMock(ResponseInterface::class);
        $forbidden->expects($this->once())->method('getBody')->willReturn($stream);
        
        return $forbidden;
    }
    
    
    public function requestProvider()
    {
        $requestAttribute = $this->createMock(ServerRequestInterface::class);
        $requestAttribute->expects($this->once())->method('getAttribute')
            ->with('authz')
            ->willReturn('user');

        $requestRoute = $this->createMock(ServerRequestInterface::class);
        $requestRoute->expects($this->exactly(2))->method('getAttribute')
            ->withConsecutive(['authz'], ['route'])
            ->willReturnOnConsecutiveCalls(null, (object)['authz' => 'user']);

        $requestRouteBC = $this->createMock(ServerRequestInterface::class);
        $requestRouteBC->expects($this->exactly(2))->method('getAttribute')
            ->withConsecutive(['authz'], ['route'])
            ->willReturnOnConsecutiveCalls(null, ['auth' => 'user']);
        
        return [
            [$requestAttribute],
            [$requestRoute],
            [$requestRouteBC]
        ];
    }
    
    public function testAllowedWithNoCheck()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $authz = $this->createAuthzMock(null);
        $next = $this->createCallbackMock($this->once(), $this->response);
        
        $middleware = new Middleware($authz);
        $response = $middleware($request, $this->response, $next);
        
        $this->assertSame($this->response, $response);
    }
    
    /**
     * @dataProvider requestProvider
     * @param ServerRequestInterface|\PHPUnit_Framework_MockObject_MockObject $request
     */
    public function testAllowed(ServerRequestInterface $request)
    {
        $authz = $this->createAuthzMock('user', true);
        $next = $this->createCallbackMock($this->once(), $this->response);
        
        $middleware = new Middleware($authz);
        $response = $middleware($request, $this->response, $next);
        
        $this->assertSame($this->response, $response);
    }
    
    /**
     * @dataProvider requestProvider
     * @param ServerRequestInterface|\PHPUnit_Framework_MockObject_MockObject $request
     */
    public function testDeniedNoUser(ServerRequestInterface $request)
    {
        $forbidden = $this->createForbiddenMock();
        $authz = $this->createAuthzMock('user', false);
        $next = $this->createCallbackMock($this->never());
        
        $this->response->expects($this->once())->method('withStatus')
            ->with(401)
            ->willReturn($forbidden);
        
        $middleware = new Middleware($authz);
        
        $response = $middleware($request, $this->response, $next);
        
        $this->assertSame($forbidden, $response);
    }
    
    /**
     * @dataProvider requestProvider
     * @param ServerRequestInterface|\PHPUnit_Framework_MockObject_MockObject $request
     */
    public function testDeniedForbidden(ServerRequestInterface $request)
    {
        $forbidden = $this->createForbiddenMock();
        $authz = $this->createAuthzMock('user', false, true);
        $next = $this->createCallbackMock($this->never());
        
        $this->response->expects($this->once())->method('withStatus')
            ->with(403)
            ->willReturn($forbidden);
        
        $middleware = new Middleware($authz);
        
        $response = $middleware($request, $this->response, $next);
        
        $this->assertSame($forbidden, $response);
    }
    
    
    public function testNoUserCallback()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getAttribute')
            ->with('authz')
            ->willReturn('user');
        
        $deniedResponse = $this->createMock(ResponseInterface::class);
        $authz = $this->createAuthzMock('user', false, false);
        $next = $this->createCallbackMock($this->never());
        
        $noUserCallback = $this->createCallbackMock($this->once(), $deniedResponse);
        
        $middleware = new Middleware($authz, $noUserCallback);
        
        $response = $middleware($request, $this->response, $next);
        
        $this->assertSame($deniedResponse, $response);
    }
    
    public function testForbiddenCallback()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getAttribute')
            ->with('authz')
            ->willReturn('user');
        
        $deniedResponse = $this->createMock(ResponseInterface::class);
        $authz = $this->createAuthzMock('user', false, true);
        $next = $this->createCallbackMock($this->never());
        
        $forbiddenCallback = $this->createCallbackMock($this->once(), $deniedResponse);
        
        $middleware = new Middleware($authz, 401, $forbiddenCallback);
        
        $response = $middleware($request, $this->response, $next);
        
        $this->assertSame($deniedResponse, $response);
    }
    
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage noUser argument should be an integer or callable
     */
    public function testInvalidNoUserCallback()
    {
        $authz = $this->createAuthzMock(null);
        new Middleware($authz, 'foo bar zoo');
    }    
    
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage forbidden argument should be an integer or callable
     */
    public function testInvalidForbiddenCallback()
    {
        $authz = $this->createAuthzMock(null);
        new Middleware($authz, 401, 'foo bar zoo');
    }    
    
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage next method should be a callback
     */
    public function testInvalidNext()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $authz = $this->createAuthzMock(null);
        
        $middleware = new Middleware($authz);
        
        $middleware($request, $this->response, 'foo bar zoo');
    }    
}
