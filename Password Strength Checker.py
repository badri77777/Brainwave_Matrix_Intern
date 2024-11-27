import re

# Function to check password length
def check_length(password):
    # Minimum length should be 12 characters
    if len(password) < 12:
        return False, "Password is too short. It should be at least 12 characters long."
    return True, "Length is acceptable."

# Function to check password complexity (uppercase, lowercase, digit, special character)
def check_complexity(password):
    # Check for uppercase letters
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    # Check for lowercase letters
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    # Check for digits
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    # Check for special characters
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    
    return True, "Password has acceptable complexity."

# Function to check for commonly used or weak passwords
def check_uniqueness(password):
    weak_passwords = [
        "password", "123456", "123456789", "qwerty", "abc123", "password1", "letmein",
        "welcome", "admin", "sunshine", "12345"
    ]
    if password.lower() in weak_passwords:
        return False, "Password is too common. Choose a more unique password."
    
    return True, "Password is unique."

# Main function to evaluate password strength
def evaluate_password(password):
    # Check password length
    is_length_valid, length_feedback = check_length(password)
    if not is_length_valid:
        return f"Password Strength: Weak\nFeedback: {length_feedback}"
    
    # Check password complexity
    is_complexity_valid, complexity_feedback = check_complexity(password)
    if not is_complexity_valid:
        return f"Password Strength: Weak\nFeedback: {complexity_feedback}"
    
    # Check password uniqueness
    is_unique, uniqueness_feedback = check_uniqueness(password)
    if not is_unique:
        return f"Password Strength: Weak\nFeedback: {uniqueness_feedback}"
    
    # If all checks pass, password is strong
    return "Password Strength: Strong\nFeedback: Your password is strong. Good job!"

# Main program to take user input and check password
if __name__ == "__main__":
    print("Welcome to the Password Strength Checker!")
    user_password = input("Enter a password to check its strength: ")
    result = evaluate_password(user_password)
    print(result)
