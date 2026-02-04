<?php
require_once('models/Users.php');

class AuthController
{
    private $user;

    public function __construct()
    {
        $this->user = new User();
    }

    // register
    public function register($name, $email, $password, $confirm_password)
    {
        $errors = [];

        if (empty($name)) {
            $errors[] = "Full name is required";
        }
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Valid email is required";
        }
        if (empty($password)) {
            $errors[] = "Password is required";
        }
        if (strlen($password) < 6) {
            $errors[] = "Password must be at least 6 characters";
        }
        if ($password !== $confirm_password) {
            $errors[] = "Passwords do not match";
        }
        // Email existing checking
        $this->user->email = $email;
        if ($this->user->emailExists()) {
            $errors[] = "Email already exists";
        }

        // If no errors create user
        if (empty($errors)) {
            $this->user->name = $name;
            $this->user->email = $email;
            $this->user->password = $password;

            if ($this->user->create()) {
                $_SESSION['success'] = "Registration successfull! Please Login.";
                header("Location: login.php");
                exit();
            } else {
                $errors[] = "Registration failed. Please try again.";
            }

        }
        return $errors;
    }

    public function login($email, $password)
    {
        $errors = [];

        if (empty($email)) {
            $errors[] = "Email is required";
        }
        if (empty($password)) {
            $errors[] = "Password is required.";
        }

        if (empty($errors)) {
            $this->user->email = $email;

            if ($this->user->emailExists()) {
                if (password_verify($password, $this->user->password)) {
                    $_SESSION['user_id'] = $this->user->id;
                    $_SESSION['user_name'] = $this->user->name;
                    $_SESSION['user_email'] = $this->user->email;
                    $_SESSION['logged_in'] = true;

                    header("Location: dashboard.php");
                    exit();
                } else {
                    $errors[] = "Invalid Password";
                }
            } else {
                $errors[] = "Email not found";
            }
        }
        return $errors;
    }

    public function logout()
    {
        $_SESSION = array();
        session_destroy();
        header("Location: login.php");
        exit();
    }

    public function isLoggedIn()
    {
        return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
    }

    public function getCurrentUser()
    {
        if ($this->isLoggedIn()) {
            return [
                'id' => $_SESSION['user_id'],
                'name' => $_SESSION['user_name'],
                'email' => $_SESSION['user_email']
            ];
        }
        return null;
    }

    public function updateProfile($name, $email)
    {
        $errors = [];

        if (empty($name)) {
            $errors[] = "Name is required";
        }
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Valid email is required";
        }

        if (empty($errors)) {
            $this->user->id = $_SESSION['user_id'];
            $this->user->name = $name;
            $this->user->email = $email;

            if ($this->user->update()) {
                $_SESSION['user_name'] = $name;
                $_SESSION['user_email'] = $email;
                $_SESSION['success'] = "Profile updated successfully";
                return true;
            } else {
                $errors[] = "update failed";
            }
        }
        return $errors;
    }

    public function changePassword($current_password, $new_password, $confirm_password)
    {
        $errors = [];

        if (empty($current_password)) {
            $errors[] = "Current password is required";
        }
        if (empty($new_password)) {
            $errors[] = "New password is required";
        }
        if (strlen($new_password) < 6) {
            $errors[] = "New password must be at least 6 characters";
        }
        if ($new_password !== $confirm_password) {
            $errors[] = "New passwords do not match";
        }

        if (empty($errors)) {
            $this->user->email = $_SESSION['user_email'];
            $this->user->emailExists();

            if (password_verify($current_password, $this->user->password)) {
                $this->user->id = $_SESSION['user_id'];
                $this->user->password = $new_password;

                if ($this->user->updatePassword()) {
                    $_SESSION['success'] = "Password changed successfully";
                    return true;
                } else {
                    $errors[] = "Password change failed";
                }
            } else {
                $errors[] = "Current Password is incorrect";
            }
        }
        return $errors;
    }

}