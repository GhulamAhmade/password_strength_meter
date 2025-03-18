import streamlit as st
import re
import random
import string

def generate_strong_password(use_lowercase=True, use_uppercase=True, use_digits=True, use_special=True, 
                           avoid_similar=True, avoid_hard_special=True, avoid_patterns=True, 
                           easy_to_read=True, min_length=8):
    """Generate a strong password based on user preferences."""
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_chars = "!@#$%^&*"
    
    # Characters to avoid if avoid_similar is True
    similar_chars = "l1I0O" if avoid_similar else ""
    
    # Filter out similar-looking characters if requested
    if avoid_similar:
        lowercase = ''.join(c for c in lowercase if c not in similar_chars)
        uppercase = ''.join(c for c in uppercase if c not in similar_chars)
        digits = ''.join(c for c in digits if c not in similar_chars)
    
    # Filter out hard-to-type special characters if requested
    if avoid_hard_special:
        special_chars = "!@#$%"
    
    # Select characters based on user preferences
    lowercase = lowercase if use_lowercase else ""
    uppercase = uppercase if use_uppercase else ""
    digits = digits if use_digits else ""
    special_chars = special_chars if use_special else ""
    
    # Ensure at least one of each selected character type
    password = []
    if use_lowercase:
        password.append(random.choice(lowercase))
    if use_uppercase:
        password.append(random.choice(uppercase))
    if use_digits:
        password.append(random.choice(digits))
    if use_special:
        password.append(random.choice(special_chars))
    
    # Fill the rest randomly with selected character types
    all_chars = lowercase + uppercase + digits + special_chars
    
    # Generate password avoiding patterns if requested
    while len(password) < min_length:
        new_char = random.choice(all_chars)
        if avoid_patterns and len(password) > 0:
            # Avoid repeating the same character
            while new_char == password[-1]:
                new_char = random.choice(all_chars)
            # Avoid patterns like "123" or "abc"
            if len(password) > 1:
                while (new_char == chr(ord(password[-1]) + 1) and 
                       password[-1] == chr(ord(password[-2]) + 1)):
                    new_char = random.choice(all_chars)
        password.append(new_char)
    
    # Shuffle the password
    random.shuffle(password)
    return ''.join(password)

def check_password_strength(password):
    """Check password strength and provide feedback."""
    score = 0
    feedback = []
    requirements = {
        "length": False,
        "uppercase": False,
        "lowercase": False,
        "digits": False,
        "special": False
    }
    
    # Length Check
    if len(password) >= 8:
        score += 1
        requirements["length"] = True
    else:
        feedback.append("❌ Password should be at least 8 characters long.")
    
    # Upper & Lowercase Check
    if re.search(r"[A-Z]", password):
        score += 1
        requirements["uppercase"] = True
    if re.search(r"[a-z]", password):
        score += 1
        requirements["lowercase"] = True
    if not (requirements["uppercase"] and requirements["lowercase"]):
        feedback.append("❌ Include both uppercase and lowercase letters.")
    
    # Digit Check
    if re.search(r"\d", password):
        score += 1
        requirements["digits"] = True
    else:
        feedback.append("❌ Add at least one number (0-9).")
    
    # Special Character Check
    if re.search(r"[!@#$%^&*]", password):
        score += 1
        requirements["special"] = True
    else:
        feedback.append("❌ Include at least one special character (!@#$%^&*).")
    
    # Strength Rating
    if score >= 4:
        feedback.append("✅ Strong Password!")
    elif score >= 2:
        feedback.append("⚠️ Moderate Password - Consider adding more security features.")
    else:
        feedback.append("❌ Weak Password - Improve it using the suggestions above.")
    
    return score, feedback, requirements

def estimate_crack_time(password):
    """Estimate time to crack the password."""
    char_set_size = 0
    if re.search(r"[a-z]", password):
        char_set_size += 26
    if re.search(r"[A-Z]", password):
        char_set_size += 26
    if re.search(r"\d", password):
        char_set_size += 10
    if re.search(r"[!@#$%^&*]", password):
        char_set_size += 8
    
    if char_set_size == 0:
        return "Instant"
    
    combinations = char_set_size ** len(password)
    # Assuming 1 billion attempts per second
    seconds = combinations / 1_000_000_000
    
    if seconds < 60:
        return "Less than a minute"
    elif seconds < 3600:
        return f"{int(seconds/60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds/3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds/86400)} days"
    else:
        return f"{int(seconds/31536000)} years"

def main():
    st.set_page_config(
        page_title="Password Strength Meter",
        page_icon="🔐",
        layout="centered"
    )
    
    # Custom CSS for better styling
    st.markdown("""
        <style>
        .main {
            max-width: 800px;
            margin: 0 auto;
        }
        .stProgress .st-bo {
            background-color: #1f77b4;
        }
        .stButton>button {
            width: 100%;
            margin-top: 10px;
            background-color: #1f77b4;
            color: white;
            border: none;
            padding: 10px;
            border-radius: 5px;
        }
        .stButton>button:hover {
            background-color: #1565c0;
        }
        h1, h2, h3 {
            color: #1f77b4;
        }
        .password-box {
            background-color: #f0f2f6;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .strength-meter {
            height: 20px;
            background: linear-gradient(to right, #ff4444, #ffbb33, #00C851);
            border-radius: 10px;
            margin: 10px 0;
        }
        .requirement-item {
            display: flex;
            align-items: center;
            margin: 5px 0;
        }
        .requirement-item i {
            margin-right: 10px;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Title and description
    st.title("🔐 Password Strength Meter")
    st.markdown("""
        This tool evaluates your password's strength based on security criteria and provides feedback for improvement.
    """)
    st.markdown("---")
    
    # Create tabs
    tab1, tab2, tab3, tab4 = st.tabs(["Check Password", "Generate Password", "Compare Passwords", "Password Tips"])
    
    with tab1:
        st.subheader("Check Your Password")
        password = st.text_input("Enter your password:", type="password", key="check_password_input")
        
        # Real-time password strength meter
        if password:
            score, feedback, requirements = check_password_strength(password)
            strength = score/5  # Normalize to 0-1
            
            # Display strength meter
            st.markdown("### Password Strength")
            st.progress(strength)
            
            # Display strength indicator with color
            if score >= 4:
                st.success("Strong Password! ✅")
            elif score >= 2:
                st.warning("Moderate Password ⚠️")
            else:
                st.error("Weak Password ❌")
            
            # Display requirements checklist
            st.markdown("### Requirements Checklist")
            for req, met in requirements.items():
                if met:
                    st.markdown(f"✅ {req.title()}")
                else:
                    st.markdown(f"❌ {req.title()}")
            
            # Display feedback messages
            st.markdown("### Feedback")
            for message in feedback:
                st.markdown(message)
        
        check_button = st.button("Check Password", key="check_password_button")
    
    with tab2:
        st.subheader("Generate Strong Password")
        
        # Password category selection
        st.markdown("### Select Password Category")
        category = st.selectbox(
            "Choose a category for your password:",
            ["General Use", "Email Account", "Banking", "Social Media", "Custom"]
        )
        
        # Set default requirements based on category
        if category == "Email Account":
            min_length = 12
            use_special = True
            use_uppercase = True
            use_lowercase = True
            use_digits = True
        elif category == "Banking":
            min_length = 16
            use_special = True
            use_uppercase = True
            use_lowercase = True
            use_digits = True
        elif category == "Social Media":
            min_length = 10
            use_special = True
            use_uppercase = True
            use_lowercase = True
            use_digits = True
        else:
            min_length = 8
            use_special = True
            use_uppercase = True
            use_lowercase = True
            use_digits = True
        
        # Password generation options
        st.markdown("### Select Password Requirements")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Basic Requirements")
            use_lowercase = st.checkbox("Include lowercase letters (a-z)", value=use_lowercase)
            use_uppercase = st.checkbox("Include uppercase letters (A-Z)", value=use_uppercase)
            use_digits = st.checkbox("Include numbers (0-9)", value=use_digits)
            use_special = st.checkbox("Include special characters (!@#$%^&*)", value=use_special)
        
        with col2:
            st.markdown("#### Advanced Options")
            avoid_similar = st.checkbox("Avoid similar-looking characters (l,1,I,0,O)", value=True)
            avoid_hard_special = st.checkbox("Use only common special characters (!@#$%)", value=True)
            avoid_patterns = st.checkbox("Avoid repeated characters and patterns", value=True)
            easy_to_read = st.checkbox("Generate easy-to-read password", value=True)
        
        min_length = st.slider("Minimum password length", min_value=8, max_value=32, value=min_length)
        num_passwords = st.slider("Number of passwords to generate", min_value=1, max_value=5, value=1)
        
        if st.button("Generate New Password(s)", key="generate_password_button"):
            if not any([use_lowercase, use_uppercase, use_digits, use_special]):
                st.error("Please select at least one character type for the password!")
            else:
                for i in range(num_passwords):
                    strong_password = generate_strong_password(
                        use_lowercase=use_lowercase,
                        use_uppercase=use_uppercase,
                        use_digits=use_digits,
                        use_special=use_special,
                        avoid_similar=avoid_similar,
                        avoid_hard_special=avoid_hard_special,
                        avoid_patterns=avoid_patterns,
                        easy_to_read=easy_to_read,
                        min_length=min_length
                    )
                    
                    # Create a container for each password
                    with st.container():
                        st.markdown(f"### Password {i+1}")
                        st.code(strong_password, language="text")
                
                # Display which criteria were met
                st.markdown("### Password Criteria Met")
                if use_lowercase:
                    st.markdown("✅ Contains lowercase letters")
                if use_uppercase:
                    st.markdown("✅ Contains uppercase letters")
                if use_digits:
                    st.markdown("✅ Includes numbers")
                if use_special:
                    st.markdown("✅ Has special characters")
                if avoid_similar:
                    st.markdown("✅ Avoids similar-looking characters")
                if avoid_hard_special:
                    st.markdown("✅ Uses only common special characters")
                if avoid_patterns:
                    st.markdown("✅ Avoids repeated characters and patterns")
                if easy_to_read:
                    st.markdown("✅ Easy to read and type")
                st.markdown(f"✅ Minimum length of {min_length} characters")
    
    with tab3:
        st.subheader("Compare Passwords")
        st.markdown("Enter two passwords to compare their strength.")
        
        # Password input fields
        password1 = st.text_input("Enter first password:", type="password", key="compare_password1")
        password2 = st.text_input("Enter second password:", type="password", key="compare_password2")
        
        # Compare button
        if st.button("Compare Passwords", key="compare_button"):
            if not password1 or not password2:
                st.error("Please enter both passwords to compare.")
            else:
                # Get strength scores and requirements
                score1, feedback1, requirements1 = check_password_strength(password1)
                score2, feedback2, requirements2 = check_password_strength(password2)
                
                # Display comparison results
                st.markdown("### Comparison Results")
                
                # Determine which password is stronger
                if score1 > score2:
                    st.success(f"Password 1 is stronger than Password 2 by {score1 - score2} points")
                elif score2 > score1:
                    st.success(f"Password 2 is stronger than Password 1 by {score2 - score1} points")
                else:
                    st.info("Both passwords have the same strength score")
                
                # Display detailed comparison
                st.markdown("#### Detailed Comparison")
                
                # Create columns for side-by-side comparison
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Password 1**")
                    st.markdown(f"Strength Score: {score1}/5")
                    st.markdown("Requirements Met:")
                    for req, met in requirements1.items():
                        if met:
                            st.markdown(f"✅ {req.title()}")
                        else:
                            st.markdown(f"❌ {req.title()}")
                
                with col2:
                    st.markdown("**Password 2**")
                    st.markdown(f"Strength Score: {score2}/5")
                    st.markdown("Requirements Met:")
                    for req, met in requirements2.items():
                        if met:
                            st.markdown(f"✅ {req.title()}")
                        else:
                            st.markdown(f"❌ {req.title()}")
                
                # Display differences
                st.markdown("#### Key Differences")
                differences = []
                for req in requirements1.keys():
                    if requirements1[req] != requirements2[req]:
                        differences.append(f"- Password 1 {'meets' if requirements1[req] else 'does not meet'} the {req} requirement, while Password 2 {'meets' if requirements2[req] else 'does not meet'} it")
                
                if differences:
                    for diff in differences:
                        st.markdown(diff)
                else:
                    st.info("Both passwords meet the same requirements")
                
                # Character analysis
                st.markdown("#### Character Analysis")
                
                # Length comparison
                len1, len2 = len(password1), len(password2)
                if len1 != len2:
                    st.markdown(f"- Password 1 is {abs(len1 - len2)} characters {'longer' if len1 > len2 else 'shorter'} than Password 2")
                
                # Character type comparison
                char_types1 = {
                    "uppercase": len(re.findall(r"[A-Z]", password1)),
                    "lowercase": len(re.findall(r"[a-z]", password1)),
                    "digits": len(re.findall(r"\d", password1)),
                    "special": len(re.findall(r"[!@#$%^&*]", password1))
                }
                
                char_types2 = {
                    "uppercase": len(re.findall(r"[A-Z]", password2)),
                    "lowercase": len(re.findall(r"[a-z]", password2)),
                    "digits": len(re.findall(r"\d", password2)),
                    "special": len(re.findall(r"[!@#$%^&*]", password2))
                }
                
                for char_type in char_types1.keys():
                    if char_types1[char_type] != char_types2[char_type]:
                        st.markdown(f"- Password 1 has {abs(char_types1[char_type] - char_types2[char_type])} more {char_type} characters than Password 2")
    
    with tab4:
        st.subheader("Password Tips & Best Practices")
        
        # Common password mistakes
        st.markdown("### Common Password Mistakes to Avoid")
        st.markdown("""
        ❌ Using personal information:
        - Birthdays
        - Names of family members or pets
        - Addresses
        - Phone numbers
        
        ❌ Using common patterns:
        - Sequential numbers (123456)
        - Keyboard patterns (qwerty)
        - Repeated characters (aaaaaa)
        - Common words with simple substitutions (p@ssw0rd)
        
        ❌ Using the same password for multiple accounts
        ❌ Using very short passwords
        ❌ Using only letters or only numbers
        """)
        
        # Good password examples
        st.markdown("### Good Password Examples")
        st.markdown("""
        ✅ Strong passwords:
        - `K9#mP2$vL5nX8`
        - `R7@jH4*wQ9pN3`
        - `T5$kM8#nB2vL6`
        
        ❌ Weak passwords:
        - `password123`
        - `12345678`
        - `qwerty123`
        - `admin123`
        """)
        
        # Additional security tips
        st.markdown("### Additional Security Tips")
        st.markdown("""
        1. Use a password manager to store your passwords securely
        2. Enable two-factor authentication whenever possible
        3. Change your passwords regularly
        4. Never share your passwords with anyone
        5. Use different passwords for different accounts
        6. Be careful with password recovery questions
        7. Log out of accounts when you're done
        8. Keep your devices and software updated
        9. Be wary of phishing attempts
        10. Monitor your accounts for suspicious activity
        """)
    
    # Add password requirements in an expander
    with st.expander("📋 Password Requirements"):
        st.markdown("""
        A strong password should meet these criteria:
        
        - Minimum 8 characters long
        - Contains both uppercase and lowercase letters
        - Includes at least one number (0-9)
        - Contains at least one special character (!@#$%^&*)
        
        ### Additional Security Tips:
        
        - Avoid using personal information (birthdays, names, etc.)
        - Don't use common words or phrases
        - Use different passwords for different accounts
        - Consider using a password manager
        - Regularly change your passwords
        - Enable two-factor authentication when possible
        
        ### Password Strength Levels:
        
        - **Strong**: Meets all basic requirements and is hard to guess
        - **Moderate**: Meets most requirements but could be improved
        - **Weak**: Missing important security features
        
        The stronger your password, the better protected your accounts will be!
        """)

if __name__ == "__main__":
    main()
