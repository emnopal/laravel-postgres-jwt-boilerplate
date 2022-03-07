<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class UserController extends Controller
{

    /**
     * Create a new UserController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api');
    }

    /**
     * Get the authenticated User.
     *
     * @return JsonResponse
     */
    public function userProfile(Request $request): JsonResponse
    {
        if ($request->query('show_token') == 'true' || $request->query('show_token') == '1') {
            return response()->json([
                "user" => auth()->user(),
                "token" => $request->header('Authorization'),
            ]);
        } else {
            return response()->json([
                "user" => auth()->user(),
            ]);
        }
    }
}
