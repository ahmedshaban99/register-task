<!DOCTYPE html>
<html>
<head>
    <title>Registration</title>
</head>
<body>
    <h2>Registration</h2>
    <form action="register_process.php" method="POST">
        <label for="username">Username:</label>
        <input type="text" name="username" required><br><br>
        
        <label for="email">Email:</label>
        <input type="email" name="email" required><br><br>
        
        <label for="password">Password:</label>
        <input type="password" name="password" required><br><br>
        
        <label for="confirm_password">Confirm Password:</label>
        <input type="password" name="confirm_password" required><br><br>
        
        <input type="submit" value="Register">
    </form>
    <?php
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {    $username = $_POST["username"];
    $email = $_POST["email"];
    $password = $_POST["password"];
    $confirm_password = $_POST["confirm_password"];

    if ($password != $confirm_password) {
        echo "Password and confirm password do not match. Please try again.";
    } else {
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);

        $db_host = "localhost";
        $db_user = "your_db_user";
        $db_password = "your_db_password";
        $db_name = "your_db_name";

        $conn = mysqli_connect($db_host, $db_user, $db_password, $db_name);

        if (!$conn) {
            die("Database connection failed: " . mysqli_connect_error());
        }

        $sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
        $stmt = mysqli_prepare($conn, $sql);
        mysqli_stmt_bind_param($stmt, "sss", $username, $email, $hashed_password);

        if (mysqli_stmt_execute($stmt)) {
            header("Location: login.php");
            exit();
        } else {
            echo "Registration failed. Please try again later.";
        }

        mysqli_stmt_close($stmt);
        mysqli_close($conn);
    }
}
?>


</body>
</html>
