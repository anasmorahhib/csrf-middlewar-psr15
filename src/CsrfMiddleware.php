<?php

namespace Morahhib\Csrf;

use Morahhib\Csrf\Exceptions\InvalidCsrfException;
use Morahhib\Csrf\Exceptions\NoCsrfException;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class CsrfMiddleware implements MiddlewareInterface
{

    /**
     * @var array|\ArrayAccess
     */
    private $session;

    /**
     * @var string
     */
    private $sessionKey;

    /**
     * @var string
     */
    private $formKey;

    /**
     * @var int
     */
    private $limit;



    /**
     * CsrfMiddleware constructor.
     *
     * @param array|\ArrayAccess $session
     * @param string             $sessionKey
     * @param string             $formKey
     */
    public function __construct(
        &$session,
        string $sessionKey = 'csrf.tokens',
        string $formKey = '_csrf',
        int $limit = 50
    ) {
        $this->testSession($session);
        $this->session = &$session;
        $this->sessionKey = $sessionKey;
        $this->formKey = $formKey;
        $this->limit = $limit;
    }

    /**
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * 
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (in_array($request->getMethod(), ['GET', 'POST'], true)) {
            $params = $request->getParsedBody() ?: [];
            if (!array_key_exists($this->formKey, $params)) {
                throw new NoCsrfException();
            }
            if (!\in_array($params[$this->formKey], $this->session[$this->sessionKey] ?? [], true)) {
                throw new InvalidCsrfException();
            }

            $this->removeToken($params[$this->formKey]);
        }
        return $handler->handle($request);
    }

    /**
     * Generate random token
     * @return string
     */
    public function generateToken(): string
    {
        $token = md5(random_bytes(16));
        $tokens = $this->session[$this->sessionKey] ?? [];
        $tokens[] = $token;
        $this->session[$this->sessionKey] = $this->limitTokens($tokens);

        return $token;
    }

    /**
     * @param mixed $session
     * 
     * @return void
     * 
     * @throws \TypeError
     */
    private function testSession($session): void
    {
        if (!\is_array($session) && !$session instanceof \ArrayAccess) {
            throw new \TypeError('session is not an array');
        }
    }


    /**
     * @param string $token
     * 
     * @return void
     */
    private function removeToken(string $token): void
    {
        $this->session[$this->sessionKey] = array_filter(
            $this->session[$this->sessionKey] ?? [],
            function ($t) use ($token) {
                return $token !== $t;
            }
        );
    }

    /**
     * @param array $tokens
     * 
     * @return array
     */
    private function limitTokens(array $tokens): array
    {
        if (\count($tokens) > $this->limit) {
            array_shift($tokens);
        }

        return $tokens;
    }


    /**
     * @return string
     */
    public function getSessionKey(): string
    {
        return $this->sessionKey;
    }

    /**
     * @return string
     */
    public function getFormKey(): string
    {
        return $this->formKey;
    }
}
