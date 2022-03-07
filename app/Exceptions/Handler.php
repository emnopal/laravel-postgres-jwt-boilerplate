<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Exception\RouteNotFoundException;
use Illuminate\Auth\AuthenticationException;
use Throwable;

class Handler extends ExceptionHandler
{
    /**
     * A list of the exception types that are not reported.
     *
     * @var array<int, class-string<Throwable>>
     */
    protected $dontReport = [
        //
    ];

    /**
     * A list of the inputs that are never flashed for validation exceptions.
     *
     * @var array<int, string>
     */
    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
    ];

    /**
     * Register the exception handling callbacks for the application.
     *
     * @return void
     */
    public function register()
    {
        $this->reportable(function (Throwable $e) {
            //
        });
    }

    /**
     * Handling Throwable or Exception
     *
     * @param Request $request, Throwable $exception
     *
     * @return void
     */
    public function render($request, Throwable $exception)
    {
        if ($exception instanceof NotFoundHttpException) {
            return response()->json([
                'status' => 'error',
                'status_code' => 404,
                'message' => 'Route not Found' . $exception->getMessage(),
            ], 404);
        }
        if ($exception instanceof RouteNotFoundException) {
            return response()->json([
                'status' => 'error',
                'status_code' => 404,
                'message' => 'Route not Found' . $exception->getMessage(),
            ], 404);
        }
        if ($exception instanceof AuthenticationException) {
            return response()->json([
                'status' => 'error',
                'status_code' => 401,
                'message' => $exception->getMessage() . ' Invalid token. Login or Register to Continue',
            ], 401);
        }
        if ($exception instanceof MethodNotAllowedHttpException) {
            return response()->json([
                'status' => 'error',
                'status_code' => 401,
                'message' => 'Method not allowed: ' . $exception->getMessage(),
            ], 401);
        }
        return parent::prepareJsonResponse($request, $exception);
    }
}
