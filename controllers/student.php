<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class StudentController{
  public function update_user_by_id(){
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $data = json_decode(file_get_contents("php://input"), true);
    $user_id = htmlspecialchars(isset($data['user_id']) ? $data['user_id'] : '');
    $student_number = htmlspecialchars(isset($data['student_number']) ? $data['student_number'] : '');

    // Create a new instance for api key validation
    $api_key = new SecurityKey($conn);
    $api_response = $api_key->validateBearerToken();
    
    if ($api_response['status'] === 'error') {
      echo json_encode($api_response);
      return;
    }
    
    // Check if the user's role is 'student'
    if ($api_response['role'] !== 'student') {
      echo json_encode([
        'status' => 'error', 
        'message' => 'Unauthorized access'
      ]);
      return;
    }

    if(empty($user_id)){
      $response['status'] = 'error';
      $response['message'] = 'User ID cannot be empty';
      echo json_encode($response);
      return;
    }

    if(empty($student_number)){
      $response['status'] = 'error';
      $response['message'] = 'Student number cannot be empty';
      echo json_encode($response);
      return;
    }

    $stmt = $conn->prepare("UPDATE users SET student_number = ? WHERE user_id = ?");
    $stmt->bind_param("ss", $student_number, $user_id);

    if ($stmt->execute()){
      $response['status'] = 'success';
      $response['message'] = 'Student number updated successfully';
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error updating student number: ' . $conn->error;
      echo json_encode($response);
      return;
    }

    $stmt->close();
  }
  
  public function get_user_by_id(){
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $user_id = htmlspecialchars(isset($_GET['uid']) ? $_GET['uid'] : '');

    // Create a new instance for api key validation
    $api_key = new SecurityKey($conn);
    $api_response = $api_key->validateBearerToken();
    
    if ($api_response['status'] === 'error') {
      echo json_encode($api_response);
      return;
    }
    
    // Check if the user's role is 'student'
    if ($api_response['role'] !== 'student') {
      echo json_encode([
        'status' => 'error', 
        'message' => 'Unauthorized access'
      ]);
      return;
    }

    if(empty($user_id)){
      $response['status'] = 'error';
      $response['message'] = 'User ID cannot be empty';
      echo json_encode($response);
      return;
    }

    // Check if user do not exists
    $stmt = $conn->prepare("SELECT * FROM users WHERE user_id = ?");
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();

    // Check if the user exists
    if ($result->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'This user do not exist';
      echo json_encode($response);
      return;
    }

    $user = $result->fetch_assoc();

    $response['status'] = 'success';
    $response['user'] = [
      'profile' => $user['profile'],
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

  public function verify_user(){
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $email = htmlspecialchars(isset($_GET['email']) ? $_GET['email'] : '');
    $token = htmlspecialchars(isset($_GET['token']) ? $_GET['token'] : '');

    if (empty($token)) {
      $response['status'] = 'error';
      $response['message'] = 'Token cannot be empty';
      echo json_encode($response);
      return;
    }

    if (empty($email)) {
      $response['status'] = 'error';
      $response['message'] = 'Email cannot be empty';
      echo json_encode($response);
      return;
    }

    // Check if email exists
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ? AND user_id = ?");
    $stmt->bind_param("ss", $email, $token);
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();

    // Check if the user exists
    if ($result->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'This user does not exist';
      echo json_encode($response);
      return;
    }

    $user = $result->fetch_assoc();

    // Check if the user is already verified
    if ($user['status'] === 'verified') {
      $response['status'] = 'success';
      $response['message'] = 'User is already verified';
      echo json_encode($response);
      return;
    }

    $verification_link = "http://localhost/capstone2/api/student/verify?email=" . urlencode($email) . "&token=" . urlencode($token);

    // Send the verification email
    $title = "Account Verification";
    $subject = "Verify Your Account";
    $body = "Hello " . ucwords(strtolower($user['first_name'])) . ",<br><br>Please click the link below to verify your account:<br><a href='" . $verification_link . "'>Verify My Account</a><br><br>Thank you!";

    if (mail($email, $subject, $body, "From: razonmarknicholas.cdlb@gmail.com")) {
      $response['status'] = 'success';
      $response['message'] = 'Verification email sent successfully';
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'sucerrorcess';
      $response['message'] = 'Failed to send verification email';
      echo json_encode($response);
      return;
    }
  }

  public function update_user_status(){
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    $email = htmlspecialchars(isset($_GET['email']) ? $_GET['email'] : '');
    $token = htmlspecialchars(isset($_GET['token']) ? $_GET['token'] : '');
  
    // Check if the token and email are provided
    if (empty($token)) {
      $response['status'] = 'error';
      $response['message'] = 'Token cannot be empty';
      echo json_encode($response);
      return;
    }
  
    if (empty($email)) {
      $response['status'] = 'error';
      $response['message'] = 'Email cannot be empty';
      echo json_encode($response);
      return;
    }
  
    // Verify if the user exists with the given email and token
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ? AND user_id = ?");
    $stmt->bind_param("ss", $email, $token);
    $stmt->execute();
    $result = $stmt->get_result();
  
    if ($result->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid token or user does not exist';
      echo json_encode($response);
      return;
    }
  
    $user = $result->fetch_assoc();
  
    // Check if the user is already verified
    if ($user['status'] === 'verified') {
      $response['status'] = 'success';
      $response['message'] = 'User is already verified';
      echo json_encode($response);
      return;
    }
  
    // Update user status to 'verified'
    $stmt = $conn->prepare("UPDATE users SET status = 'verified' WHERE email = ? AND user_id = ?");
    $stmt->bind_param("ss", $email, $token);
  
    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'User verified successfully';
      header('location: http://localhost:3000/student/account');
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Failed to update user status';
      echo json_encode($response);
      return;
    }

    $stmt->close();
  }  
}
?>