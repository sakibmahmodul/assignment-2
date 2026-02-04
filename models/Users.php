<?php
require_once 'config/Database.php';

class User
{
    private $conn;
    private $table_name = 'users';

    public $id;
    public $name;
    public $email;
    public $password;
    public $created_at;

    public function __construct()
    {
        $database = new Database();
        $this->conn = $database->getConnection();
    }

    // Create user (Registration)
    public function create()
    {
        $query = "INSERT INTO `" . $this->table_name . "` 
                  SET name = :name, email = :email, password = :password";

        $stmt = $this->conn->prepare($query);

        // Sanitize and bind
        $this->name = htmlspecialchars(strip_tags($this->name));
        $this->email = htmlspecialchars(strip_tags($this->email));

        // Hash password
        $this->password = password_hash($this->password, PASSWORD_DEFAULT);

        $stmt->bindParam(":name", $this->name);
        $stmt->bindParam(":email", $this->email);
        $stmt->bindParam(":password", $this->password);

        if ($stmt->execute()) {
            return true;
        }
        return false;
    }

    // Check if email exists
    public function emailExists()
    {
        $query = "SELECT id, name, email, password 
                  FROM `" . $this->table_name . "` 
                  WHERE email = :email 
                  LIMIT 0,1";

        $stmt = $this->conn->prepare($query);

        // Sanitize and bind
        $this->email = htmlspecialchars(strip_tags($this->email));
        $stmt->bindParam(":email", $this->email);

        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $this->id = $row['id'];
            $this->name = $row['name'];
            $this->email = $row['email'];
            $this->password = $row['password'];
            return true;
        }
        return false;
    }

    // Get user by ID
    public function getUserById($id)
    {
        $query = "SELECT id, name, email, created_at 
                  FROM `" . $this->table_name . "` 
                  WHERE id = :id";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":id", $id);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    // Update user profile
    public function update()
    {
        $query = "UPDATE `" . $this->table_name . "` 
                  SET name = :name, email = :email 
                  WHERE id = :id";

        $stmt = $this->conn->prepare($query);

        $this->name = htmlspecialchars(strip_tags($this->name));
        $this->email = htmlspecialchars(strip_tags($this->email));

        $stmt->bindParam(":name", $this->name);
        $stmt->bindParam(":email", $this->email);
        $stmt->bindParam(":id", $this->id);

        if ($stmt->execute()) {
            return true;
        }
        return false;
    }

    // Update password
    public function updatePassword()
    {
        $query = "UPDATE `" . $this->table_name . "` 
                  SET password = :password 
                  WHERE id = :id";

        $stmt = $this->conn->prepare($query);

        $this->password = password_hash($this->password, PASSWORD_DEFAULT);

        $stmt->bindParam(":password", $this->password);
        $stmt->bindParam(":id", $this->id);

        if ($stmt->execute()) {
            return true;
        }
        return false;
    }
}
?>