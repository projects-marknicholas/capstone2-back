<?php
use myPHPnotes\Microsoft\Auth;
use myPHPnotes\Microsoft\Handlers\Session;
use myPHPnotes\Microsoft\Models\User;
session_start();

class AuthController {
  public function login(){ 
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $data = json_decode(file_get_contents("php://input"), true);
    $email = htmlspecialchars(isset($data['email']) ? $data['email'] : '');
    $password = htmlspecialchars(isset($data['password']) ? $data['password'] : '');
    $created_at = date('Y-m-d H:i:s');

    if(empty($email)){
      $response['status'] = 'error';
      $response['message'] = 'Email cannot be empty';
      echo json_encode($response);
      return;
    } else if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
      $response['status'] = 'error';
      $response['message'] = 'Invalid email format';
      echo json_encode($response);
      return;
    }

    if(empty($password)){
      $response['status'] = 'error';
      $response['message'] = 'Password cannot be empty';
      echo json_encode($response);
      return;
    }

    // Check if user details are correct
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();

    if ($result->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'Email or password is incorrect';
      echo json_encode($response);
      return;
    }

    $user = $result->fetch_assoc();

    if (!password_verify($password, $user['password'])) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid email or password.';
      echo json_encode($response);
      return;
    } else {
      // Check if the user is deactivated
      if ($user['status'] === 'deactivated') {
        $response['status'] = 'error';
        $response['message'] = 'Your account has been deactivated.';
        echo json_encode($response);
        return;
      }

      // Check if the role is pending
      if ($user['role'] === 'pending') {
        $response['status'] = 'error';
        $response['message'] = 'Your account is not yet approved.';
        echo json_encode($response);
        return;
      }

      // Update the last_login field upon successful login
      $update_stmt = $conn->prepare("UPDATE users SET last_login = ? WHERE email = ?");
      $update_stmt->bind_param("ss", $created_at, $email);
      $update_stmt->execute();
      $update_stmt->close();

      $response['status'] = 'success';
      $response['message'] = 'Login successful.';
      $response['user'] = [
        'api_key' => $user['api_key'],
        'profile' => $user['profile'],
        'user_id' => $user['user_id'],
        'student_number' => $user['student_number'],
        'email' => $user['email'],
        'first_name' => ucwords(strtolower($user['first_name'])),
        'last_name' => ucwords(strtolower($user['last_name'])),
        'role' => $user['role'],
        'status' => $user['status']
      ];
      echo json_encode($response);
      return;
    }
  }

  public function register(){
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $data = json_decode(file_get_contents("php://input"), true);
    $user_id = bin2hex(random_bytes(16));
    $profile = 'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png';
    $first_name = htmlspecialchars(isset($data['first_name']) ? $data['first_name'] : '');
    $last_name = htmlspecialchars(isset($data['last_name']) ? $data['last_name'] : '');
    $email = htmlspecialchars(isset($data['email']) ? $data['email'] : '');
    $password = htmlspecialchars(isset($data['password']) ? $data['password'] : '');
    $confirm_password = htmlspecialchars(isset($data['confirm_password']) ? $data['confirm_password'] : '');
    $role = 'pending';
    $created_at = date('Y-m-d H:i:s');
    $api_key = bin2hex(random_bytes(16));

    if(empty($first_name)){
      $response['status'] = 'error';
      $response['message'] = 'First name cannot be empty';
      echo json_encode($response);
      return;
    }

    if(empty($last_name)){
      $response['status'] = 'error';
      $response['message'] = 'Last name cannot be empty';
      echo json_encode($response);
      return;
    }

    if(empty($email)){
      $response['status'] = 'error';
      $response['message'] = 'Email cannot be empty';
      echo json_encode($response);
      return;
    } else if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
      $response['status'] = 'error';
      $response['message'] = 'Invalid email format';
      echo json_encode($response);
      return;
    }

    if(empty($password)){
      $response['status'] = 'error';
      $response['message'] = 'Password cannot be empty';
      echo json_encode($response);
      return;
    } else if(strlen($password) < 6){
      $response['status'] = 'error';
      $response['message'] = 'Password must be at least 6 characters long';
      echo json_encode($response);
      return;
    } else if(!preg_match('/[A-Z]/', $password)){
      $response['status'] = 'error';
      $response['message'] = 'Password must contain at least one uppercase letter';
      echo json_encode($response);
      return;
    } else if(!preg_match('/[a-z]/', $password)){
      $response['status'] = 'error';
      $response['message'] = 'Password must contain at least one lowercase letter';
      echo json_encode($response);
      return;
    } else if(!preg_match('/\d/', $password)){
      $response['status'] = 'error';
      $response['message'] = 'Password must contain at least one number';
      echo json_encode($response);
      return;
    }

    if(empty($confirm_password)){
      $response['status'] = 'error';
      $response['message'] = 'Confirm Password cannot be empty';
      echo json_encode($response);
      return;
    } else if($password != $confirm_password){
      $response['status'] = 'error';
      $response['message'] = 'Password do not match';
      echo json_encode($response);
      return;
    }

    // Check if the user already exists
    $stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'This user already exists';
      echo json_encode($response);
      return;
    }

    $stmt->close();

    // Insert data
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $conn->prepare('INSERT INTO users (user_id, profile, first_name, last_name, email, password, role, api_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->bind_param('sssssssss', $user_id, $profile, $first_name, $last_name, $email, $hashed_password, $role, $api_key, $created_at);
    
    if ($stmt->execute()){
      $response['status'] = 'success';
      $response['message'] = 'User created successfully';
      echo json_encode($response);
      return;
    } else{
      $response['status'] = 'error';
      $response['message'] = 'Error creating user: ' . $conn->error;
      echo json_encode($response);
      return;
    }
  }

  public function forgot_password() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $data = json_decode(file_get_contents("php://input"), true);
    $email = htmlspecialchars(isset($data['email']) ? $data['email'] : '');

    if (empty($email)) {
      $response['status'] = 'error';
      $response['message'] = 'Email cannot be empty';
      echo json_encode($response);
      return;
    } else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid email format';
      echo json_encode($response);
      return;
    }

    // Check if the email exists in the database
    $stmt = $conn->prepare("SELECT id, first_name FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'No user found with this email address';
      echo json_encode($response);
      return;
    }

    $user = $result->fetch_assoc();
    $token = bin2hex(random_bytes(16));

    // Update the token in the database
    $stmt = $conn->prepare("UPDATE users SET token = ? WHERE email = ?");
    $stmt->bind_param("ss", $token, $email);

    if($stmt->execute()){
      $response['status'] = 'success';
      $response['message'] = 'Token generated successfully';
      $response['data'] = array(
        'first_name' => ucwords(strtolower($user['first_name'])),
        'email' => $email,
        'token' => $token
      );

      echo json_encode($response);
      return;
    } else{
      $response['status'] = 'error';
      $response['message'] = 'Failed to update token';
      echo json_encode($response);
      return;
    }

    $stmt->close();
  }
  
  public function reset_password() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $data = json_decode(file_get_contents("php://input"), true);
    $email = htmlspecialchars(isset($_GET['email']) ? $_GET['email'] : '');
    $token = htmlspecialchars(isset($_GET['token']) ? $_GET['token'] : '');
    $new_password = htmlspecialchars(isset($data['new_password']) ? $data['new_password'] : '');
    $confirm_password = htmlspecialchars(isset($data['confirm_password']) ? $data['confirm_password'] : '');

    if (empty($email)) {
      $response['status'] = 'error';
      $response['message'] = 'Email cannot be empty';
      echo json_encode($response);
      return;
    } else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid email format';
      echo json_encode($response);
      return;
    }

    if (empty($token)) {
      $response['status'] = 'error';
      $response['message'] = 'Token cannot be empty';
      echo json_encode($response);
      return;
    }

    if (empty($new_password)) {
      $response['status'] = 'error';
      $response['message'] = 'New password cannot be empty';
      echo json_encode($response);
      return;
    } else if (strlen($new_password) < 6) {
      $response['status'] = 'error';
      $response['message'] = 'Password must be at least 6 characters long';
      echo json_encode($response);
      return;
    } else if (!preg_match('/[A-Z]/', $new_password)) {
      $response['status'] = 'error';
      $response['message'] = 'Password must contain at least one uppercase letter';
      echo json_encode($response);
      return;
    } else if (!preg_match('/[a-z]/', $new_password)) {
      $response['status'] = 'error';
      $response['message'] = 'Password must contain at least one lowercase letter';
      echo json_encode($response);
      return;
    } else if (!preg_match('/\d/', $new_password)) {
      $response['status'] = 'error';
      $response['message'] = 'Password must contain at least one number';
      echo json_encode($response);
      return;
    }

    if (empty($confirm_password)) {
      $response['status'] = 'error';
      $response['message'] = 'Confirm Password cannot be empty';
      echo json_encode($response);
      return;
    } else if ($new_password != $confirm_password) {
      $response['status'] = 'error';
      $response['message'] = 'Passwords do not match';
      echo json_encode($response);
      return;
    }

    // Check if the token is valid
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? AND token = ?");
    $stmt->bind_param("ss", $email, $token);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'Invalid token or email';
      echo json_encode($response);
      return;
    }

    // Token is valid, update the password
    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
    $stmt = $conn->prepare("UPDATE users SET password = ?, token = NULL WHERE email = ?");
    $stmt->bind_param("ss", $hashed_password, $email);

    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'Password reset successfully';
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error resetting password: ' . $conn->error;
      echo json_encode($response);
      return;
    }
    
    $stmt->close();
  }

  public function microsoft_signin(){
    $tenant = "common";
    $client_id = "3e3ec2ce-f7af-4f40-91c4-cd537e80203e";
    $client_secret = "cf.8Q~bOMXNq17Mu3gGiUTlhnUQWMAA2sewMha.Q";
    $callback = "http://localhost/uph-college/api/auth/microsoft";
    $scopes = ["User.Read"];

    $microsoft = new Auth($tenant, $client_id, $client_secret, $callback, $scopes);
    $authUrl = $microsoft->getAuthUrl();
    echo $authUrl;
    $parsedUrl = parse_url($authUrl);
    parse_str($parsedUrl['query'], $queryParams);
    $stateFromUrl = isset($queryParams['state']) ? $queryParams['state'] : 'State not found';
    Session::set('oauth_state', $stateFromUrl);
    header("location: " . $microsoft->getAuthUrl());
  }

  public function microsoft_auth() {
    // Check if state matches
    if (!isset($_REQUEST['state']) || $_REQUEST['state'] !== Session::get('oauth_state')) {
      echo json_encode(['status' => 'error', 'message' => 'Invalid state parameter.']);
      return;
    }

    // Initialize the Auth object with session credentials
    $auth = new Auth(
      Session::get("tenant_id"),
      Session::get("client_id"),
      Session::get("client_secret"),
      Session::get("redirect_uri"),
      Session::get("scopes")
    );
  
    // Retrieve tokens
    $tokens = $auth->getToken($_REQUEST['code'], $_REQUEST['state']);
    $accessToken = $tokens->access_token;
  
    // Set the access token to the Auth object
    $auth->setAccessToken($accessToken);
  
    // Fetch user data
    $user = new User();
    $surname = $user->data->getSurname();
    $givenName = $user->data->getGivenName();
    $email = $user->data->getUserPrincipalName();
  
    // Check if the user already exists
    global $conn; // Ensure you have access to the database connection
    $stmt = $conn->prepare("SELECT profile, user_id, first_name, last_name, role, status, email FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
  
    if ($result->num_rows > 0) {
      // User exists, fetch user details
      $userData = $result->fetch_assoc();
      $stmt->close();
  
      // Return user credentials
      $response = [
        'status' => 'success',
        'message' => 'Login successful.',
        'user' => [
          'profile' => $userData['profile'] ?? null,
          'user_id' => $userData['user_id'] ?? null,
          'email' => $userData['email'],
          'first_name' => ucwords(strtolower($userData['first_name'] ?? '')),
          'last_name' => ucwords(strtolower($userData['last_name'] ?? '')),
          'role' => $userData['role'] ?? null,
          'status' => $userData['status'] ?? null
        ]
      ];
      echo json_encode($response);
      return;
    }
  
    // If the user does not exist, register the user
    $user_id = bin2hex(random_bytes(16));
    $profile = 'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png';
    $role = 'pending';
    $joined_at = date('Y-m-d H:i:s');
    $security_key = bin2hex(random_bytes(16));
  
    // Insert new user into the database
    $stmt = $conn->prepare('INSERT INTO users (user_id, profile, last_name, first_name, email, password, role, security_key, joined_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
    // Set the password to a random string or any default password since it's a social login
    $defaultPassword = password_hash($user_id, PASSWORD_DEFAULT);
    $stmt->bind_param('sssssssss', $user_id, $profile, $surname, $givenName, $email, $defaultPassword, $role, $security_key, $joined_at);
  
    if ($stmt->execute()) {
      $stmt->close();
  
      $response = [
        'status' => 'success',
        'message' => 'User registered successfully.',
        'user' => [
          'profile' => $profile,
          'user_id' => $user_id,
          'email' => $email,
          'first_name' => ucwords(strtolower($givenName)),
          'last_name' => ucwords(strtolower($surname)),
          'role' => $role,
          'status' => 'pending'
        ]
      ];
      echo json_encode($response);
    } else {
      $stmt->close();
      $response = [
        'status' => 'error',
        'message' => 'Error creating user: ' . $conn->error
      ];
      echo json_encode($response);
    }
  } 
}
?>