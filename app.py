# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, session, send_file, after_this_request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, ImageHistory
from bg_remover import BackgroundRemover
import uuid
import psutil
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['PROCESSED_FOLDER'] = os.path.join('static', 'processed')

# Ensure upload directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROCESSED_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create background remover
bg_remover = BackgroundRemover()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        
        if existing_user:
            flash('Username already exists', 'danger')
            return render_template('register.html')
        
        if existing_email:
            flash('Email already exists', 'danger')
            return render_template('register.html')
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password, tokens=5)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! You now have 5 free tokens.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's image history
    history = ImageHistory.query.filter_by(user_id=current_user.id).order_by(ImageHistory.created_at.desc()).all()
    return render_template('dashboard.html', history=history)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('admin.html', users=users)

@app.route('/admin/add_tokens', methods=['POST'])
@login_required
def add_tokens():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    user_id = request.form.get('user_id')
    tokens = request.form.get('tokens', type=int)
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    user.tokens += tokens
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'Added {tokens} tokens to {user.username}',
        'newTotal': user.tokens
    })

@app.route('/admin/create_user', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    tokens = request.form.get('tokens', type=int, default=0)
    is_admin = request.form.get('is_admin') == 'on'
    
    existing_user = User.query.filter_by(username=username).first()
    existing_email = User.query.filter_by(email=email).first()
    
    if existing_user:
        return jsonify({'success': False, 'message': 'Username already exists'}), 400
    
    if existing_email:
        return jsonify({'success': False, 'message': 'Email already exists'}), 400
    
    hashed_password = generate_password_hash(password)
    new_user = User(
        username=username, 
        email=email, 
        password=hashed_password, 
        tokens=tokens,
        is_admin=is_admin
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'User {username} created successfully',
        'user': {
            'id': new_user.id,
            'username': new_user.username,
            'email': new_user.email,
            'tokens': new_user.tokens,
            'is_admin': new_user.is_admin
        }
    })
# app.py (continued)

def log_memory_usage(tag=""):
    """Log the current memory usage"""
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    print(f"MEMORY [{tag}]: {mem_info.rss / 1024 / 1024:.2f} MB RSS")

# Memory cleanup background task
def delayed_memory_cleanup():
    """Run delayed cleanup to free memory after request completes"""
    time.sleep(2)  # Wait for response to be sent
    import gc
    gc.collect()
    log_memory_usage("after gc")

@app.route('/process', methods=['POST'])
@login_required
def process_image():
    log_memory_usage("start")
    
    # Check if user has tokens
    if current_user.tokens <= 0:
        return jsonify({
            'success': False,
            'message': 'You have no tokens left. Please contact admin to add more tokens.'
        }), 400
    
    # Check if the post request has the file part
    if 'image' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'}), 400
        
    file = request.files['image']
    
    # If user does not select file, browser also submits an empty part without filename
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400
        
    # Check if the file is allowed
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'tif', 'webp', 'jif', 'jfif', 'heif', 'heic', 'ico', 'svg', 'jp2'}
    if '.' not in file.filename or \
       file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return jsonify({'success': False, 'message': 'File type not allowed'}), 400
    
    # Clean up previous files if they exist
    if 'current_original' in session:
        try:
            original_path = os.path.join(app.root_path, 'static', session['current_original'])
            if os.path.exists(original_path):
                os.remove(original_path)
        except Exception as e:
            app.logger.error(f"Error removing previous original file: {e}")
    
    if 'current_processed' in session:
        try:
            processed_path = os.path.join(app.root_path, 'static', session['current_processed'])
            if os.path.exists(processed_path):
                os.remove(processed_path)
        except Exception as e:
            app.logger.error(f"Error removing previous processed file: {e}")
    
    # Save the uploaded file
    filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
    upload_folder = os.path.join(app.root_path, 'static', 'uploads')
    os.makedirs(upload_folder, exist_ok=True)
    upload_path = os.path.join(upload_folder, filename)
    file.save(upload_path)
    
    try:
        # Process the image
        processed_folder = os.path.join(app.root_path, 'static', 'processed')
        os.makedirs(processed_folder, exist_ok=True)
        processed_path = bg_remover.remove_background(
            upload_path, 
            processed_folder
        )
        
        # Log memory after processing
        log_memory_usage("after processing")
        
        # Get relative paths for storage
        original_relative = os.path.relpath(upload_path, os.path.join(app.root_path, 'static'))
        processed_relative = os.path.relpath(processed_path, os.path.join(app.root_path, 'static'))
        
        # Store current image paths in session
        session['current_original'] = original_relative
        session['current_processed'] = processed_relative
        
        # Decrease token count
        current_user.tokens -= 1
        db.session.commit()
        
        # Get the hostname dynamically
        host_url = request.host_url.rstrip('/')
        
        # Construct absolute URLs for images
        original_url = f"{host_url}/static/{original_relative}"
        processed_url = f"{host_url}/static/{processed_relative}"
        
        # Print debugging info
        print(f"Original URL: {original_url}")
        print(f"Processed URL: {processed_url}")
        
        # Schedule background memory cleanup
        cleanup_thread = threading.Thread(target=delayed_memory_cleanup)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        return jsonify({
            'success': True,
            'message': 'Image processed successfully',
            'original': original_url,
            'processed': processed_url,
            'download_url': url_for('download_file', filename=processed_relative),
            'remaining_tokens': current_user.tokens
        })
    
    except Exception as e:
        # If error, clean up the uploaded file
        if os.path.exists(upload_path):
            os.remove(upload_path)
        return jsonify({'success': False, 'message': f'Error processing image: {str(e)}'}), 500

@app.route('/history/<int:history_id>/delete', methods=['POST'])
@login_required
def delete_history(history_id):
    history = ImageHistory.query.get_or_404(history_id)
    
    # Ensure the history item belongs to the current user
    if history.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    # Delete the image files
    try:
        original_path = os.path.join('static', history.original_image)
        processed_path = os.path.join('static', history.processed_image)
        
        if os.path.exists(original_path):
            os.remove(original_path)
        
        if os.path.exists(processed_path):
            os.remove(processed_path)
    except Exception as e:
        # Continue even if files can't be deleted
        print(f"Error deleting files: {str(e)}")
    
    # Delete the record
    db.session.delete(history)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'History deleted successfully'})

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    user = User.query.get_or_404(user_id)
    
    # Delete all user's history
    histories = ImageHistory.query.filter_by(user_id=user.id).all()
    for history in histories:
        try:
            original_path = os.path.join('static', history.original_image)
            processed_path = os.path.join('static', history.processed_image)
            
            if os.path.exists(original_path):
                os.remove(original_path)
            
            if os.path.exists(processed_path):
                os.remove(processed_path)
        except Exception as e:
            print(f"Error deleting files: {str(e)}")
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'User {user.username} deleted successfully'})

@app.route('/download/<path:filename>')
@login_required
def download_file(filename):
    """Download a file and prepare to delete it after response is sent"""
    try:
        # Construct the file path
        file_path = os.path.join(app.root_path, 'static', filename)
        
        # Check if file exists
        if not os.path.exists(file_path):
            flash('File not found', 'error')
            return redirect(url_for('dashboard'))
        
        # Get the filename for the download
        download_name = os.path.basename(file_path)
        
        # Return the file
        return send_file(file_path, as_attachment=True, download_name=download_name)
    
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/cleanup_files', methods=['POST'])
def cleanup_files():
    """Clean up temporary files when user leaves the page"""
    if 'current_original' in session:
        try:
            original_path = os.path.join(app.root_path, 'static', session['current_original'])
            if os.path.exists(original_path):
                os.remove(original_path)
        except Exception as e:
            app.logger.error(f"Error removing original file: {e}")
    
    if 'current_processed' in session:
        try:
            processed_path = os.path.join(app.root_path, 'static', session['current_processed'])
            if os.path.exists(processed_path):
                os.remove(processed_path)
        except Exception as e:
            app.logger.error(f"Error removing processed file: {e}")
    
    # Clear session variables
    session.pop('current_original', None)
    session.pop('current_processed', None)
    
    return '', 204  # Return empty response with "No Content" status

# Initialize the database
with app.app_context():
    db.create_all()
    
    # Create admin user if doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@example.com',
            password=generate_password_hash('admin123'),
            is_admin=True,
            tokens=999999
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
