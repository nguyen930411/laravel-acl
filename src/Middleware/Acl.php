<?php
namespace Nguyen930411\Acl\Middleware;

use Closure;
use Auth;

class Acl
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {
        if (Auth::guard($guard)->check()) {
            $routeName = $request->route()->getName();

            if (Auth::guard($guard)->user()->role->is_admin || Auth::guard($guard)->user()->hasPermissionTo($routeName)) {
                return $next($request);
            }
        }

        if ($request->isJson() || $request->wantsJson()) {
            return response()->json([
                'error' => [
                    'status_code' => 401,
                    'code'        => 'INSUFFICIENT_PERMISSIONS',
                    'description' => trans('errors.401'),
                ],
            ], 401);
        }

        return abort(401, trans('errors.401'));
    }
}
