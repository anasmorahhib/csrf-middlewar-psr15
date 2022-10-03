<?php

namespace Morahhib\Csrf\Test;

use PHPUnit\Framework\TestCase;
use Morahhib\Csrf\CsrfMiddleware;
use Morahhib\Csrf\Exceptions\NoCsrfException;
use Morahhib\Csrf\Exceptions\InvalidCsrfException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class CsrfMiddlewareTest extends TestCase
{

    private function makeMiddleware(&$session = [])
    {
        return new CsrfMiddleware($session);
    }

    private function makeResponse()
    {
        return $this->getMockBuilder(ResponseInterface::class)->getMock();
    }

    private function makeRequest(string $method = 'GET', ?array $params = null): ServerRequestInterface
    {
        $request = $this->getMockBuilder(ServerRequestInterface::class)->getMock();
        $request->method('getMethod')->willReturn($method);
        $request->method('getParsedBody')->willReturn($params);

        return $request;
    }

    private function makeRequestHandler(): RequestHandlerInterface
    {
        $handler = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $handler->method('handle')->willReturn($this->makeResponse());
        return $handler;
    }

    public function testAcceptValidSession()
    {
        $a = [];
        $b = $this->getMockBuilder(\ArrayAccess::class)->getMock();
        $middlewarea = $this->makeMiddleware($a);
        $middlewareb = $this->makeMiddleware($b);
        $this->assertInstanceOf(CsrfMiddleware::class, $middlewarea);
        $this->assertInstanceOf(CsrfMiddleware::class, $middlewareb);
    }

    public function testRejectInvalidSession()
    {
        $this->expectException(\TypeError::class);
        $a = new \stdClass();
        $middlewarea = $this->makeMiddleware($a);
    }

    function testGetPass()
    {
        $middleware = $this->makeMiddleware();
        $token = $middleware->generateToken();
        $handler = $this->makeRequestHandler();
        $handler->expects($this->once())->method('handle');

        $middleware->process($this->makeRequest('GET', ['_csrf' => $token]), $handler);
    }

    function testPreventPost()
    {
        $middleware = $this->makeMiddleware();
        $handler = $this->makeRequestHandler();
        $handler->expects($this->never())->method('handle');
        $this->expectException(NoCsrfException::class);
        $middleware->process($this->makeRequest('POST'), $handler);
    }

    function testPostSuceessfullyWithToken()
    {
        $middleware = $this->makeMiddleware();
        $token = $middleware->generateToken();

        $handler = $this->makeRequestHandler();
        $handler->expects($this->once())->method('handle')->willReturn($this->makeResponse());
        $middleware->process($this->makeRequest('POST', ['_csrf' => $token]), $handler);
    }

    function testPostErrorWithToken()
    {
        $middleware = $this->makeMiddleware();
        $token = 'fake token';
        //$token = $middleware->generateToken();
        $handler = $this->makeRequestHandler();
        $handler->expects($this->never())->method('handle');
        $this->expectException(InvalidCsrfException::class);
        $middleware->process($this->makeRequest('POST', ['_csrf' => $token]), $handler);
    }

    public function testPostWithDoubleToken()
    {
        $middleware = $this->makeMiddleware();
        $token = $middleware->generateToken();
        $handler = $this->makeRequestHandler();
        $handler->expects($this->once())->method('handle')->willReturn($this->makeResponse());
        $middleware->process(
            $this->makeRequest('POST', ['_csrf' => $token]),
            $handler
        );
        $this->expectException(InvalidCsrfException::class);
        $middleware->process(
            $this->makeRequest('POST', ['_csrf' => $token]),
            $handler
        );
    }

    public function testLimitTokens()
    {
        $session = [];
        $middleware = $this->makeMiddleware($session);
        for ($i = 0; $i < 100; ++$i) {
            $token = $middleware->generateToken();
        }
        $this->assertCount(50, $session[$middleware->getSessionKey()]);
        $this->assertSame($token, $session[$middleware->getSessionKey()][49]);
    }
}
