<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Vite;
use Symfony\Component\HttpFoundation\Response;

/**
 * Add security Headers to incoming requests
 *
 * @param  Closure(Request): (Response)  $next
 */
class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! $request->secure() && app()->environment('production')) {
            return redirect()->secure($request->getRequestUri());
        }

        Vite::useCspNonce();

        /** @var Response $response */
        $response = $next($request);

        // We will only apply these headers in production
        if (app()->environment('local')) {
            return $response;
        }

        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // Strict Transport Security
        $response->headers->set(
            'Strict-Transport-Security',
            'max-age=31536000; includeSubDomains',
            true
        );

        // Content Security Policy
        $response->headers->set(
            'Content-Security-Policy',
            "script-src 'nonce-".Vite::cspNonce()."' 'strict-dynamic'; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script';",
            true
        );

        // Referrer Policy
        $response->headers->set(
            'Referrer-Policy',
            'strict-origin',
            true
        );

        // Permissions Policy
        $response->headers->set(
            'Permissions-Policy',
            'autoplay=(), battery=(), cross-origin-isolated=(), execution-while-not-rendered=()',
            true
        );

        return $response;
    }
}
