<?php
require 'config.php';
require 'router.php';
require 'key.php';

// Controllers
require 'controllers/auth.php';
require 'controllers/admin.php';
require 'controllers/student.php';
require 'vendor/autoload.php';

// Initialize Router
$router = new Router();

// Auth
$router->post('/api/auth/register', 'AuthController@register');
$router->post('/api/auth/login', 'AuthController@login');
$router->post('/api/auth/forgot-password', 'AuthController@forgot_password');
$router->post('/api/auth/reset-password', 'AuthController@reset_password');
$router->get('/api/auth/microsoft', 'AuthController@microsoft_auth');

// Student
$router->get('/api/student/user', 'StudentController@get_user_by_id');
$router->put('/api/student/user', 'StudentController@update_user_by_id');
$router->get('/api/student/verification', 'StudentController@verify_user');
$router->get('/api/student/verify', 'StudentController@update_user_status');

// Admin
$router->get('/api/admin/accounts', 'AdminController@accounts');
$router->put('/api/admin/accounts', 'AdminController@update_account_status');

// Dispatch the request
$router->dispatch();
?>