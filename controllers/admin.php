<?php
class AdminController {
  public function accounts() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    // Get the current page, limit, and search query from the request
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $records_per_page = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
    $search = isset($_GET['search']) ? "%" . $_GET['search'] . "%" : null;
  
    $offset = ($page - 1) * $records_per_page;
  
    // Validate API key and role
    $api_key = new SecurityKey($conn);
    $api_response = $api_key->validateBearerToken();
  
    if ($api_response['status'] === 'error') {
      echo json_encode($api_response);
      return;
    }
  
    if ($api_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Initialize query parameters array
    $query_params = [];
  
    // Count query with search functionality
    $count_query = "SELECT COUNT(*) AS total FROM users";
    if ($search) {
      $count_query .= " WHERE (first_name LIKE ? OR last_name LIKE ? OR email LIKE ?)";
      $query_params = [$search, $search, $search];
    }
    $count_stmt = $conn->prepare($count_query);
    if ($search) {
      $count_stmt->bind_param(str_repeat('s', count($query_params)), ...$query_params);
    }
    $count_stmt->execute();
    $count_result = $count_stmt->get_result();
    $total_records = $count_result->fetch_assoc()['total'];
    $count_stmt->close();
  
    // Main query to fetch filtered users
    $query = "SELECT * FROM users";
    if ($search) {
      $query .= " WHERE (first_name LIKE ? OR last_name LIKE ? OR email LIKE ?)";
    }
    $query .= " LIMIT ?, ?";
  
    $query_params = $search ? array_merge($query_params, [$offset, $records_per_page]) : [$offset, $records_per_page];
    $stmt = $conn->prepare($query);
    $stmt->bind_param($search ? str_repeat('s', count($query_params) - 2) . "ii" : "ii", ...$query_params);
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();
  
    if ($result->num_rows === 0) {
      echo json_encode(['status' => 'error', 'message' => 'No users found']);
      return;
    }
  
    $users_data = [];
    while ($user = $result->fetch_assoc()) {
      $users_data[] = [
        'user_id' => $user['user_id'],
        'profile' => $user['profile'],
        'student_number' => $user['student_number'],
        'email' => $user['email'],
        'first_name' => ucwords(strtolower($user['first_name'])),
        'last_name' => ucwords(strtolower($user['last_name'])),
        'role' => $user['role'],
        'status' => $user['status'],
        'last_login' => $user['last_login'],
        'created_at' => $user['created_at']
      ];
    }
  
    // Add pagination data to the response
    $response['pagination'] = array(
      'current_page' => $page,
      'records_per_page' => $records_per_page,
      'total_records' => $total_records,
      'total_pages' => ceil($total_records / $records_per_page)
    );
  
    // Return all users' data with pagination info
    $response['status'] = 'success';
    $response['data'] = $users_data;
    echo json_encode($response);
    return;
  }   

  public function update_account_status() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $user_id = htmlspecialchars($_GET['uid'] ?? '');
    $status = htmlspecialchars($_GET['status'] ?? '');

    // Create a new instance for API key validation
    $api_key = new SecurityKey($conn);
    $api_response = $api_key->validateBearerToken();
    
    if ($api_response['status'] === 'error') {
      echo json_encode($api_response);
      return;
    }
    
    // Check if the user's role is 'admin'
    if ($api_response['role'] !== 'admin') {
      echo json_encode([
        'status' => 'error', 
        'message' => 'Unauthorized access'
      ]);
      return;
    }

    if (empty($user_id)) {
      $response['status'] = 'error';
      $response['message'] = 'User ID cannot be empty';
      echo json_encode($response);
      return;
    }

    if (empty($status)) {
      $response['status'] = 'error';
      $response['message'] = 'Status cannot be empty';
      echo json_encode($response);
      return;
    }

    $valid_statuses = ['verified', 'accepted', 'declined', 'deactivated'];
    if (!in_array($status, $valid_statuses)) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid status value provided.';
      echo json_encode($response);
      return;
    }

    // Check if the user exists
    $stmt = $conn->prepare("SELECT user_id FROM users WHERE user_id = ?");
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();

    if ($result->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'User not found.';
      echo json_encode($response);
      return;
    }

    // Prepare the query to update the account status
    $stmt = $conn->prepare("UPDATE users SET status = ? WHERE user_id = ?");
    $stmt->bind_param("ss", $status, $user_id);
    if ($stmt->execute()){
      $response['status'] = 'success';
      $response['message'] = 'Account status updated successfully';
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error updating account status: ' . $conn->error;
      echo json_encode($response);
      return;
    }
  }
}

?>