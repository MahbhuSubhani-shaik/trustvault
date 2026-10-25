from flask import render_template, request, redirect, url_for, flash
# (Make sure you have imported your User model or database setup)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        selected_role = request.form.get('role')  # Captures 'admin', 'viewer', or 'owner'
        
        # 1. Find the user in your database
        user = User.query.filter_by(username=username).first() # Example using SQLAlchemy
        
        # 2. Validate credentials and role
        if user and user.check_password(password):
            # Optional: Check if the user's assigned role matches the selected role
            if user.role != selected_role:
                flash(f"Access denied: You do not have permissions for the {selected_role} role.", "danger")
                return render_template('login.html')
            
            # 3. Log the user in (e.g., using Flask-Login)
            # login_user(user)
            
            flash("Logged in successfully!", "success")
            return redirect(url_for('documents')) # Redirect to your main dashboard/documents page
        else:
            flash("Invalid username or password.", "danger")
            
    return render_template('login.html')
