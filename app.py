from flask import Flask, render_template, request, redirect, url_for, flash

# 1. Initialize the Flask app FIRST
app = Flask(__name__)

# (Optional: Add your app.config settings here, e.g., app.config['SECRET_KEY'] = '...')

# 2. Then paste your login route below it
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        selected_role = request.form.get('role')  # Captures 'admin', 'viewer', or 'owner'
        
        # 1. Find the user in your database
        # user = User.query.filter_by(username=username).first() # Example using SQLAlchemy
        
        # 2. Validate credentials and role
        # if user and user.check_password(password):
        #     if user.role != selected_role:
        #         flash(f"Access denied: You do not have permissions for the {selected_role} role.", "danger")
        #         return render_template('login.html')
            
        #     flash("Logged in successfully!", "success")
        #     return redirect(url_for('documents'))
        # else:
        #     flash("Invalid username or password.", "danger")
            
    return render_template('login.html')

# 3. Keep this at the very bottom of the file if you run locally
if __name__ == '__main__':
    app.run(debug=True)
