<?php

 $email = $_POST['email'];
 $pass = $_POST['pass'];

 if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die('Invalid email format');
 }

 if (strlen($pass) < 8) {
    die('Password must be at least 8 characters long');
 }

 $hash = password_hash($pass, PASSWORD_BCRYPT);

 $user = 'root';
 $password = '';

 $conn = new mysqli('localhost', $user, $password, 'user_details');

 if ($conn->connect_error) {
    die('Connect Error : ' . $conn->connect_error);
 } else {
    $stmt = $conn->prepare("INSERT INTO user_details (email, password) VALUES (?, ?)");

    $stmt->bind_param("ss", $email, $hash);

    $stmt->execute();

    if ($stmt->error) {
       die('Execution Error : ' . $stmt->error);
    } else {
       echo "Registration Success!!";
    }

    $stmt->close();
    $conn->close();
 }
?>
