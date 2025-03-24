import os
from flask import Flask , request , render_template , redirect , url_for , flash , session
from flask_sqlalchemy import SQLAlchemy 
from sqlalchemy import UniqueConstraint , or_ , and_
from datetime import datetime 
import secrets
from sqlalchemy.orm import aliased

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///iescp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    flagged = db.Column(db.Boolean, default=False)

    name = db.Column(db.String(100))
    category = db.Column(db.String(100))
    niche = db.Column(db.String(100))
    reach = db.Column(db.Integer)

    company_name = db.Column(db.String(100))
    industry = db.Column(db.String(100))
    budget = db.Column(db.Float)

    sponsor_campaign = db.relationship('Campaign', backref='sponsor_user', lazy=True)
    influencer_ad_request = db.relationship('AdRequest', backref='influencer_user', lazy=True)


    def __init__(self, email, password, role, **kwargs):
        self.email = email
        self.password = password
        self.role = role
        if role == 'influencer':
            self.name = kwargs.get('name')
            self.category = kwargs.get('category')
            self.niche = kwargs.get('niche')
            self.reach = kwargs.get('reach')
        elif role == 'sponsor':
            self.company_name = kwargs.get('company_name')
            self.industry = kwargs.get('industry')
            self.budget = kwargs.get('budget')

class Campaign(db.Model):
    __tablename__ = 'campaigns'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    budget = db.Column(db.Float)
    visibility = db.Column(db.String(50), nullable=False)  
    goals = db.Column(db.Text)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    niche = db.Column(db.String(50), nullable=False)
    flagged = db.Column(db.Boolean, default=False)

    ad_requests = db.relationship('AdRequest', backref='campaign_ad', lazy=True)

class AdRequest(db.Model):
    __tablename__ = 'ad_requests'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    requirements = db.Column(db.Text)
    payment_amount = db.Column(db.Float)
    status = db.Column(db.String(50), nullable=False, default='pending')
    verification_link = db.Column(db.String(100), nullable=True)

    campaign = db.relationship('Campaign', backref=db.backref('campaign_ad_requests', lazy=True))
    influencer = db.relationship('User', backref=db.backref('influencer_ad_requests', lazy=True))

    __table_args__ = (
        UniqueConstraint('campaign_id', 'influencer_id', name='unique_campaign_influencer'),
    )

def seed_data():
    """ Seed initial data into the database """
    with app.app_context():
        db.create_all()  # Ensure tables exist

        # Add admin user
        if not User.query.filter_by(email='admin@example.com').first():
            admin = User(email='admin@example.com', password='Admin@123', role='admin')
            db.session.add(admin)
            db.session.commit()

        # Add demo influencer
        demo_influencer = User.query.filter_by(email='influencer@example.com').first()
        if not demo_influencer:
            demo_influencer = User(
                email='influencer@example.com',
                password='Demo@123',
                role='influencer',
                name='Demo Influencer',
                category='Tech',
                niche='Gadgets',
                reach=10000
            )
            db.session.add(demo_influencer)
            db.session.commit()  # 💡 Commit here to ensure influencer exists in DB

        # Add demo sponsor
        demo_sponsor = User.query.filter_by(email='sponsor@example.com').first()
        if not demo_sponsor:
            demo_sponsor = User(
                email='sponsor@example.com',
                password='Demo@123',
                role='sponsor',
                company_name='Demo Company',
                industry='E-commerce',
                budget=5000
            )
            db.session.add(demo_sponsor)
            db.session.commit()  # 💡 Commit to ensure sponsor exists in DB

        # Add a sample campaign
        demo_campaign = Campaign.query.filter_by(name="Demo Campaign").first()
        if not demo_campaign:
            demo_campaign = Campaign(
                name="Demo Campaign",
                description="Test campaign for demo purposes",
                start_date=datetime(2025, 1, 1),
                end_date=datetime(2025, 12, 31),
                budget=1500,
                visibility="public",
                goals="Increase brand awareness",
                sponsor_id=demo_sponsor.id,
                niche="Tech"
            )
            db.session.add(demo_campaign)
            db.session.commit()  # 💡 Commit to persist campaign

        # Add a sample ad request
        if not AdRequest.query.filter_by(influencer_id=demo_influencer.id).first():
            demo_ad_request = AdRequest(
                campaign_id=demo_campaign.id,
                influencer_id=demo_influencer.id,
                requirements="Create a product review video",
                payment_amount=200,
                status="pending"
            )
            db.session.add(demo_ad_request)
            db.session.commit()  # 💡 Commit to persist ad request

        print("Demo data seeded successfully!")

with app.app_context():
    seed_data()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me')

        user = User.query.filter_by(email=email).first()

        if user and user.password == password:  
            session['user_id'] = user.id
            session['user_role'] = user.role

            if remember_me:
                session.permanent = True

            if user.role == 'influencer':
                return redirect(url_for('influencer_dashboard'))
            elif user.role == 'sponsor':
                return redirect(url_for('sponsor_dashboard'))

        flash('Invalid email or password', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me')

        user = User.query.filter_by(email=email, role='admin').first()

        if user and user.password == password: 
            session['user_id'] = user.id
            session['user_role'] = user.role

            if remember_me:
                session.permanent = True

            return redirect(url_for('admin_dashboard'))

        flash('Invalid email or password', 'danger')
        return redirect(url_for('admin_login'))

    return render_template('admin_login.html')


@app.route('/influencer_signup', methods=['GET', 'POST'])
def influencer_signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        retype_password = request.form.get('retype_password')
        category = request.form.get('category')
        niche = request.form.get('niche')
        reach = request.form.get('reach')

        if not (name, email, password, retype_password, category, niche, reach):
            flash('All fields are required.', 'danger')
            return redirect(url_for('influencer_signup'))
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already exists.', 'danger')
            return redirect(url_for('influencer_signup'))
        
        allowed_domains = ["@gmail.com", "@hotmail.com", "@yahoo.com"]
        if not any(email.endswith(domain) for domain in allowed_domains):
            flash('Email must be from a valid domain (e.g., @gmail.com, @hotmail.com, @yahoo.com).', 'danger')
            return redirect(url_for('influencer_signup'))
        
        def validate_password(password):
            if len(password) < 8:
                return False, "Password must be at least 8 characters long."
            
            has_digit = False
            has_special_char = False
            special_characters = set("!@#$%^&*(),.?\":{}|<>")

            for char in password:
                if char.isdigit():
                    has_digit = True
                if char in special_characters:
                    has_special_char = True

            if not has_digit:
                return False, "Password must contain at least one number."
            if not has_special_char:
                return False, "Password must contain at least one special character."

            return True, ""

        is_valid_password, password_error = validate_password(password)
        if not is_valid_password:
            flash(password_error, 'danger')
            return redirect(url_for('influencer_signup'))

        if password != retype_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('influencer_signup'))

        new_user = User(email=email, password=password, role='influencer', name=name, category=category, niche=niche, reach=reach)
        db.session.add(new_user)
        db.session.commit()

        flash('Influencer account created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('influencer_signup.html')

@app.route('/sponsor_signup', methods=['GET', 'POST'])
def sponsor_signup():
    if request.method == 'POST':
        company_name = request.form.get('company_name')
        industry = request.form.get('industry')
        budget = request.form.get('budget')
        email = request.form.get('email')
        password = request.form.get('password')
        retype_password = request.form.get('retype_password')

        if not (company_name and industry and budget and email and password and retype_password):
            flash('All fields are required.', 'danger')
            return redirect(url_for('sponsor_signup'))
        
        allowed_domains = ["@gmail.com", "@hotmail.com", "@yahoo.com"]
        if not any(email.endswith(domain) for domain in allowed_domains):
            flash('Email must be from a valid domain (e.g., @gmail.com, @hotmail.com, @yahoo.com).', 'danger')
            return redirect(url_for('sponsor_signup'))
        
        def validate_password(password):
            if len(password) < 8:
                return False, "Password must be at least 8 characters long."
            
            has_digit = False
            has_special_char = False
            special_characters = set("!@#$%^&*(),.?\":{}|<>")

            for char in password:
                if char.isdigit():
                    has_digit = True
                if char in special_characters:
                    has_special_char = True

            if not has_digit:
                return False, "Password must contain at least one number."
            if not has_special_char:
                return False, "Password must contain at least one special character."

            return True, ""

        is_valid_password, password_error = validate_password(password)
        if not is_valid_password:
            flash(password_error, 'danger')
            return redirect(url_for('sponsor_signup'))

        if password != retype_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('sponsor_signup'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already exists.', 'danger')
            return redirect(url_for('sponsor_signup'))

        new_user = User(email=email, password=password, role='sponsor', company_name=company_name, industry=industry, budget=budget)
        db.session.add(new_user)
        db.session.commit()

        flash('Sponsor account created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('sponsor_signup.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        if not email:
            flash('Email is required.', 'danger')
            return redirect(url_for('forgot_password'))

        # Logic to send password reset instructions (not implemented here)

        flash('Password reset instructions sent to your email.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/influencer_dashboard')
def influencer_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'influencer':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])

    active_ad_requests = db.session.query(AdRequest, Campaign).join(Campaign).filter(
        AdRequest.influencer_id == user.id,
        AdRequest.status == 'active'
    ).all()
    
    for ad_request, campaign in active_ad_requests:
        campaign_end_datetime = datetime.combine(campaign.end_date, datetime.min.time())
        
        if campaign_end_datetime < datetime.utcnow():
            ad_request.status = 'complete'
            db.session.commit()

    active_ad_requests = db.session.query(AdRequest, Campaign).join(Campaign).filter(
        AdRequest.influencer_id == user.id,
        AdRequest.status == 'active'
    ).all()

    sent_ad_requests_public = db.session.query(AdRequest, Campaign).join(Campaign).filter(
        AdRequest.influencer_id == user.id,
        AdRequest.status == 'pending',
        Campaign.visibility == 'public'
    ).all()

    received_ad_requests_private = db.session.query(AdRequest, Campaign).join(Campaign).filter(
        AdRequest.influencer_id == user.id,
        AdRequest.status == 'pending',
        Campaign.visibility == 'private'
    ).all()
    
    return render_template('influencer_dashboard.html', user=user, active_ad_requests=active_ad_requests, 
                           sent_ad_requests_public=sent_ad_requests_public, received_ad_requests_private=received_ad_requests_private)


@app.route('/accept_ad_request/<int:ad_request_id>', methods=['POST'])
def accept_ad_request(ad_request_id):

    user = User.query.get(session['user_id'])
    if user.flagged:
        flash('Your account is flagged. You cannot accept Ad Requests.', 'danger')
        return redirect(url_for('influencer_dashboard'))
    
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    ad_request.status = 'active'
    db.session.commit()
    flash('Ad request accepted successfully.')
    return redirect(url_for('influencer_dashboard'))

@app.route('/reject_ad_request/<int:ad_request_id>', methods=['POST'])
def reject_ad_request(ad_request_id):

    user = User.query.get(session['user_id'])
    if user.flagged:
        flash('Your account is flagged. You cannot reject Ad Requests.', 'danger')
        return redirect(url_for('influencer_dashboard'))
    
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    ad_request.status = 'rejected'
    db.session.commit()
    flash('Ad request rejected successfully.')
    return redirect(url_for('influencer_dashboard'))

@app.route('/cancel_ad_request/<int:ad_request_id>', methods=['POST'])
def cancel_ad_request(ad_request_id):
    if 'user_id' not in session or session.get('user_role') != 'influencer':
        return redirect(url_for('login'))

    ad_request = AdRequest.query.get(ad_request_id)
    if ad_request and ad_request.influencer_id == session['user_id']:
        ad_request.status = 'rejected'
        db.session.commit()
        flash('Ad request has been canceled.', 'success')
    else:
        flash('Ad request not found or unauthorized action.', 'danger')

    return redirect(url_for('influencer_dashboard'))

@app.route('/influencer_profile', methods=['GET', 'POST'])
def influencer_profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user.role != 'influencer':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    if user.flagged:
        flash('Your account is flagged. You cannot view Profile.', 'danger')
        return redirect(url_for('influencer_dashboard'))

    return render_template('influencer_profile.html', user=user)

@app.route('/update_influencer_profile', methods=['POST'])
def update_influencer_profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user.role != 'influencer':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    user.name = request.form['name']
    user.category = request.form['category']
    user.niche = request.form['niche']
    user.reach = request.form['reach']
    db.session.commit()
    flash('Profile updated successfully', 'success')

    return redirect(url_for('influencer_profile'))

@app.route('/influencer/completed_ad_requests')
def influencer_completed_ad_requests():
    if 'user_id' not in session or session.get('user_role') != 'influencer':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.flagged:
        flash('Your account is flagged. You cannot access Completed Ad Requests.', 'danger')
        return redirect(url_for('influencer_dashboard'))
    
    completed_ad_requests = db.session.query(AdRequest, Campaign).join(Campaign).filter(
        AdRequest.influencer_id == user.id,
        AdRequest.status == 'complete'
    ).all()
    
    return render_template('influencer_completed_ad_requests.html', user=user, completed_ad_requests=completed_ad_requests)

@app.route('/submit_verification_link/<int:ad_request_id>', methods=['POST'])
def submit_verification_link(ad_request_id):
    if 'user_id' not in session or session.get('user_role') != 'influencer':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.flagged:
        flash('Your account is flagged. You cannot submit verification link.', 'danger')
        return redirect(url_for('influencer_dashboard'))
    
    verification_link = request.form.get('verification_link')
    ad_request = AdRequest.query.get(ad_request_id)
    
    if ad_request and ad_request.influencer_id == session['user_id']:
        ad_request.verification_link = verification_link
        db.session.commit()
        flash('Verification link submitted successfully.', 'success')
    else:
        flash('Unable to submit verification link.', 'danger')
    
    return redirect(url_for('influencer_dashboard'))

@app.route('/mark_complete/<int:ad_request_id>', methods=['POST'])
def mark_complete(ad_request_id):
    if 'user_id' not in session or session.get('user_role') != 'influencer':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.flagged:
        flash('Your account is flagged. You cannot complete Ad Requests.', 'danger')
        return redirect(url_for('sponsor_dashboard'))
    
    ad_request = AdRequest.query.get(ad_request_id)
    
    if ad_request and ad_request.influencer_id == session['user_id']:
        if ad_request.verification_link:
            ad_request.status = 'complete'
            db.session.commit()
            flash('Ad request marked as complete.', 'success')
        else:
            flash('Please submit a verification link before marking as complete.', 'warning')
    else:
        flash('Unable to mark ad request as complete.', 'danger')
    
    return redirect(url_for('influencer_dashboard'))


@app.route('/sponsor_dashboard')
def sponsor_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'sponsor':
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    active_campaigns = Campaign.query.filter(
        Campaign.sponsor_id == user.id,
        Campaign.start_date <= datetime.utcnow().date(),
        Campaign.end_date >= datetime.utcnow().date()
    ).all()

    received_ad_requests_public = db.session.query(AdRequest, Campaign, User.name).select_from(AdRequest).join(
        Campaign, AdRequest.campaign_id == Campaign.id
    ).join(
        User, AdRequest.influencer_id == User.id
    ).filter(
        Campaign.sponsor_id == user.id,
        AdRequest.status == 'pending',
        Campaign.visibility == 'public'
    ).all()

    sent_ad_requests_private = db.session.query(AdRequest, Campaign, User.name).select_from(AdRequest).join(
    Campaign, AdRequest.campaign_id == Campaign.id
    ).join(
    User, AdRequest.influencer_id == User.id
    ).filter(
    Campaign.sponsor_id == user.id,
    AdRequest.status == 'pending',
    Campaign.visibility == 'private'
    ).all()


    return render_template('sponsor_dashboard.html', user=user, active_campaigns=active_campaigns,
                           received_ad_requests_public=received_ad_requests_public,
                           sent_ad_requests_private=sent_ad_requests_private)



@app.route('/accept_sponsor_ad_request/<int:ad_request_id>', methods=['POST'])
def accept_sponsor_ad_request(ad_request_id):
    if 'user_id' not in session or session.get('user_role') != 'sponsor':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.flagged:
        flash('Your account is flagged. You cannot accept Ad Requests.', 'danger')
        return redirect(url_for('sponsor_dashboard'))

    ad_request = AdRequest.query.get(ad_request_id)
    if ad_request and ad_request.campaign.sponsor_id == session['user_id']:
        ad_request.status = 'active'
        db.session.commit()
        flash('Ad request has been accepted.', 'success')
    else:
        flash('Ad request not found or unauthorized action.', 'danger')

    return redirect(url_for('sponsor_dashboard'))

@app.route('/reject_sponsor_ad_request/<int:ad_request_id>', methods=['POST'])
def reject_sponsor_ad_request(ad_request_id):
    if 'user_id' not in session or session.get('user_role') != 'sponsor':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.flagged:
        flash('Your account is flagged. You cannot reject Ad Requests.', 'danger')
        return redirect(url_for('sponsor_dashboard'))

    ad_request = AdRequest.query.get(ad_request_id)
    if ad_request and ad_request.campaign.sponsor_id == session['user_id']:
        ad_request.status = 'rejected'
        db.session.commit()
        flash('Ad request has been rejected.', 'success')
    else:
        flash('Ad request not found or unauthorized action.', 'danger')

    return redirect(url_for('sponsor_dashboard'))


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('admin_login'))
    
    today = datetime.now().date()

    user_count = User.query.count()
    sponsors_count = User.query.filter_by(role='sponsor').count()
    influencers_count = User.query.filter_by(role='influencer').count()
    active_campaigns_count = Campaign.query.filter(
        Campaign.start_date <= datetime.utcnow(),
        Campaign.end_date >= datetime.utcnow()
    ).count()
    previous_campaigns_count = Campaign.query.filter(
        Campaign.end_date < today
    ).count()
    public_campaigns_count = Campaign.query.filter_by(visibility='public').count()
    private_campaigns_count = Campaign.query.filter_by(visibility='private').count()
    ad_requests_count = AdRequest.query.count()
    created_ad_requests_count = AdRequest.query.filter_by(status='created').count()
    pending_ad_requests_count = AdRequest.query.filter_by(status='pending').count()
    active_ad_requests_count = AdRequest.query.filter_by(status='active').count()
    completed_ad_requests_count = AdRequest.query.filter_by(status='complete').count()
    rejected_ad_requests_count = AdRequest.query.filter_by(status='rejected').count()
    flagged_sponsors_count = User.query.filter_by(role='sponsor', flagged=True).count()
    flagged_influencers_count = User.query.filter_by(role='influencer', flagged=True).count()

    users = User.query.all()
    campaigns = db.session.query(User, Campaign).join(
    Campaign, User.id == Campaign.sponsor_id
    ).filter(
    User.role == 'sponsor',
    Campaign.end_date >= datetime.utcnow().date() 
    ).all()

    return render_template(
        'admin_dashboard.html', 
        user_count=user_count, 
        sponsors_count=sponsors_count,
        influencers_count=influencers_count,
        active_campaigns_count=active_campaigns_count,
        previous_campaigns_count=previous_campaigns_count,
        public_campaigns_count=public_campaigns_count, 
        private_campaigns_count=private_campaigns_count, 
        ad_requests_count=ad_requests_count, 
        created_ad_requests_count = created_ad_requests_count ,
        pending_ad_requests_count=pending_ad_requests_count, 
        active_ad_requests_count=active_ad_requests_count, 
        completed_ad_requests_count = completed_ad_requests_count ,
        rejected_ad_requests_count = rejected_ad_requests_count,
        flagged_sponsors_count=flagged_sponsors_count, 
        flagged_influencers_count=flagged_influencers_count,
        users=users, 
        campaigns=campaigns
    )

@app.route('/admin_users')
def admin_users():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin_campaigns')
def admin_campaigns():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login'))
    
    campaigns = Campaign.query.all()
    return render_template('admin_campaigns.html', campaigns=campaigns)

@app.route('/admin_ad_requests')
def admin_ad_requests():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    UserAlias = aliased(User)
    
    created_ad_requests = db.session.query(AdRequest, Campaign).select_from(
        AdRequest
    ).join(
        Campaign, AdRequest.campaign_id == Campaign.id
    ).filter(
        AdRequest.status == 'created'
    ).all()

    ad_requests = db.session.query(AdRequest, Campaign).select_from(
        AdRequest
    ).join(
        Campaign, AdRequest.campaign_id == Campaign.id
    ).filter(
        AdRequest.status.in_(['pending', 'active', 'rejected'])
    ).all()

    completed_ad_requests = db.session.query(AdRequest, Campaign, UserAlias).select_from(
    AdRequest
    ).join(
    Campaign, AdRequest.campaign_id == Campaign.id
    ).outerjoin(
    UserAlias, AdRequest.influencer_id == UserAlias.id
    ).filter(
    AdRequest.status == 'complete'
    ).all()

    expired_ad_requests = db.session.query(AdRequest, Campaign, UserAlias).select_from(
        AdRequest
    ).join(
        Campaign, AdRequest.campaign_id == Campaign.id
    ).outerjoin(
        UserAlias, AdRequest.influencer_id == UserAlias.id
    ).filter(
        AdRequest.status == 'expired'
    ).all()
    return render_template('admin_ad_requests.html', ad_requests=ad_requests, completed_ad_requests=completed_ad_requests, created_ad_requests=created_ad_requests, expired_ad_requests=expired_ad_requests)


@app.route('/flag_user/<int:user_id>', methods=['POST'])
def flag_user(user_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user:
        user.flagged = True
        user.flag_reason = request.form.get('flag_reason')
        db.session.commit()
        flash('User has been flagged.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/flag_campaign/<int:campaign_id>', methods=['POST'])
def flag_campaign(campaign_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login'))

    campaign = Campaign.query.get(campaign_id)
    if campaign:
        campaign.flagged = True
        db.session.commit()
        flash('Campaign has been flagged.', 'success')
    else:
        flash('Campaign not found.', 'danger')

    return redirect(url_for('admin_dashboard'))


@app.route('/unflag_user/<int:user_id>', methods=['POST'])
def unflag_user(user_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user:
        user.flagged = False
        user.flag_reason = None
        db.session.commit()
        flash('User has been unflagged.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/unflag_campaign/<int:campaign_id>', methods=['POST'])
def unflag_campaign(campaign_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login'))

    campaign = Campaign.query.get(campaign_id)
    if campaign:
        campaign.flagged = False
        db.session.commit()
        flash('Campaign has been unflagged.', 'success')
    else:
        flash('Campaign not found.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin_delete_campaign/<int:campaign_id>', methods=['POST'])
def admin_delete_campaign(campaign_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login'))

    campaign = Campaign.query.get(campaign_id)
    if campaign:
        db.session.delete(campaign)
        db.session.commit()
        flash('Campaign has been deleted.', 'success')
    else:
        flash('Campaign not found.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/search')
def search():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if user.flagged:
        if user.role == 'influencer':
            flash('Your account is flagged. You cannot use Search.', 'danger')
            return redirect(url_for('influencer_dashboard'))
        elif user.role == 'sponsor':
            flash('Your account is flagged. You cannot use Search.', 'danger')
            return redirect(url_for('sponsor_dashboard'))

        
    return render_template('search.html' , user=user)

@app.route('/search_campaigns')
def search_campaigns():
    if 'user_id' not in session:
        flash('You need to be logged in to search campaigns.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    campaign_query = request.args.get('query')
    niche = request.args.get('campaign_niche')
    budget = request.args.get('budget')

    campaigns = Campaign.query.filter_by(visibility='public', flagged=False)
    campaigns = campaigns.filter(Campaign.end_date >= datetime.utcnow())

    if campaign_query:
        campaigns = campaigns.filter(Campaign.name.ilike(f'%{campaign_query}%'))
    
    if niche:
        campaigns = campaigns.filter(Campaign.niche.ilike(f'%{niche}%'))
    
    if budget:
        campaigns = campaigns.filter(Campaign.budget >= float(budget))
    
    campaigns = campaigns.all()

    return render_template('search.html', user=user, campaigns=campaigns)

@app.route('/search_influencers')
def search_influencers():
    if 'user_id' not in session:
        flash('You need to be logged in to search campaigns.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    influencer_query = request.args.get('query', '')
    category = request.args.get('category', '')
    niche = request.args.get('influencer_niche', '')
    min_reach = request.args.get('min_reach', '')

    influencers = User.query.filter(User.role == 'influencer')

    if influencer_query:
        influencers = influencers.filter(User.name.like(f'%{influencer_query}%'))
    
    if category:
        influencers = influencers.filter(User.category.like(f'%{category}%'))
    
    if niche:
        influencers = influencers.filter(User.niche.like(f'%{niche}%'))
    
    if min_reach:
        try:
            min_reach = int(min_reach)
            influencers = influencers.filter(User.reach >= min_reach)
        except ValueError:
            pass  
    
    influencers = influencers.all()

    return render_template('search.html',user=user, influencers=influencers)

@app.route('/campaign_info/<int:campaign_id>', methods=['GET', 'POST'])
def campaign_info(campaign_id):
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get(user_id)
    
    campaign = Campaign.query.get_or_404(campaign_id)

    if request.method == 'POST':
        request_id = request.form.get('request_id')
        if request_id:
            existing_request = AdRequest.query.filter_by(campaign_id=campaign_id, influencer_id=user_id).first()
            if existing_request:
                flash('You have already sent a request for this campaign.', 'success')
                return redirect(url_for('campaign_info', campaign_id=campaign_id))

            elif user.role == 'sponsor' :
                flash('Sponsor cant send request.', 'danger')
            else:
                ad_request = AdRequest.query.get(request_id)
                if ad_request and ad_request.status == 'created':
                    new_ad_request = AdRequest(campaign_id=campaign_id, influencer_id=user_id, requirements=ad_request.requirements, payment_amount=ad_request.payment_amount , status='pending')
                    db.session.add(new_ad_request)
                    db.session.commit()
                    flash('Request processed successfully!', 'success')
                else:
                    flash('Invalid ad request.', 'danger')
                return redirect(url_for('sent_ad_request', campaign_id=campaign_id))

    ad_requests = db.session.query(AdRequest, Campaign).join(Campaign, AdRequest.campaign_id == Campaign.id).filter(Campaign.id == campaign_id).all()

    campaign_payments = {}
    for _, campaign in ad_requests:
        if campaign.id not in campaign_payments:
            campaign_payments[campaign.id] = 0

    for ad_req, campaign in ad_requests:
        campaign_payments[campaign.id] += ad_req.payment_amount

    processed_requests = []
    for ad_req, campaign in ad_requests:
        can_request = campaign_payments[campaign.id] <= campaign.budget
        ad_req.can_request = can_request
        processed_requests.append(ad_req)

    campaign.ad_requests = processed_requests

    return render_template('campaign_info.html',user=user, campaign=campaign)

@app.route('/sent_ad_request/<int:campaign_id>')
def sent_ad_request(campaign_id):
    return render_template('sent_ad_request.html', campaign_id=campaign_id)


@app.route('/influencer_info/<int:influencer_id>')
def influencer_info(influencer_id):
    influencer = User.query.get_or_404(influencer_id)
    return render_template('influencer_info.html', influencer=influencer)

@app.route('/sponsor_profile', methods=['GET', 'POST'])
def sponsor_profile():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if user.flagged:
        flash('Your account is flagged. You cannot update profile.', 'danger')
        return redirect(url_for('sponsor_dashboard'))
    
    if request.method == 'POST':
        user.name = request.form.get('name')
        user.budget = request.form.get('budget')
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('sponsor_profile'))

    return render_template('sponsor_profile.html', user=user)


@app.route('/campaigns', methods=['GET', 'POST'])
def campaigns():
    if 'user_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    if session.get('user_role') != 'sponsor':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    
    today = datetime.now().date()

    user = User.query.get(session['user_id'])
    if user.flagged:
        flash('Your account is flagged. You cannot access campaigns.', 'danger')
        return redirect(url_for('sponsor_dashboard'))
    
    active_campaigns = Campaign.query.filter(
        Campaign.sponsor_id == user.id,
        Campaign.end_date >= today
    ).all()

    previous_campaigns = Campaign.query.filter(
        Campaign.sponsor_id == user.id,
        Campaign.end_date < today
    ).all()

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        budget = request.form.get('budget')
        visibility = request.form.get('visibility')
        niche = request.form.get('niche')
        goals = request.form.get('goals')

        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
            return redirect(url_for('campaigns'))

        new_campaign = Campaign(
            name=name, description=description, start_date=start_date, end_date=end_date,
            budget=budget, visibility=visibility, goals=goals, sponsor_id=user.id , niche=niche
        )
        db.session.add(new_campaign)
        db.session.commit()

        flash('New campaign created successfully!', 'success')
        return redirect(url_for('campaigns'))

    return render_template('campaigns.html', active_campaigns=active_campaigns, previous_campaigns=previous_campaigns)

@app.route('/campaign/<int:campaign_id>/edit', methods=['GET', 'POST'])
def edit_campaign(campaign_id):
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.flagged:
        flash('Your account is flagged. You cannot edit campaigns.', 'danger')
        return redirect(url_for('sponsor_dashboard'))

    sponsor = User.query.get(user_id)
    if sponsor.role != 'sponsor':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign.sponsor_id != user_id:
        flash('You are not authorized to edit this campaign', 'danger')
        return redirect(url_for('sponsor_dashboard'))
    
    if campaign.flagged:
        flash('Your account is flagged. You cannot edit this campaign', 'danger')
        return redirect(url_for('campaigns'))

    if request.method == 'POST':
        campaign.name = request.form['name']
        campaign.description = request.form['description']
        
        campaign.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()
        campaign.budget = float(request.form['budget'])
        campaign.niche = request.form.get('niche')
        campaign.goals = request.form['goals']

        db.session.commit()
        flash('Campaign updated successfully!', 'success')
        return redirect(url_for('campaigns'))

    return render_template('sponsor_edit_campaign.html', user=sponsor, campaign=campaign)

@app.route('/delete_campaign/<int:campaign_id>', methods=['POST'])
def delete_campaign(campaign_id):
    if 'user_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    if session.get('user_role') != 'sponsor':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.flagged:
        flash('Your account is flagged. You cannot delete campaigns.', 'danger')
        return redirect(url_for('sponsor_dashboard'))

    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign.flagged:
        flash('Your account is flagged. You cannot delete this campaign', 'danger')
        return redirect(url_for('campaigns'))
    db.session.delete(campaign)
    db.session.commit()
    flash('Campaign deleted successfully!', 'success')
    return redirect(url_for('campaigns'))


@app.route('/sponsor_ad_request', methods=['GET', 'POST'])
def sponsor_ad_request():
    if 'user_id' not in session or session.get('user_role') != 'sponsor':
        flash('Please log in as a sponsor to access this page.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if user.flagged:
        flash('Your account is flagged. You cannot access Ad Requests.', 'danger')
        return redirect(url_for('sponsor_dashboard'))

    UserAlias = aliased(User)

    created_ad_requests = db.session.query(AdRequest, Campaign).select_from(
        AdRequest
    ).join(
        Campaign, AdRequest.campaign_id == Campaign.id
    ).filter(
        AdRequest.status == 'created'
    ).all()

    for ad_req, campaign in created_ad_requests:
        if campaign.end_date < datetime.utcnow().date():
            ad_req.status = 'expired'
            db.session.commit()

    ad_requests = db.session.query(AdRequest, Campaign, UserAlias).select_from(
        AdRequest
    ).join(
        Campaign, AdRequest.campaign_id == Campaign.id
    ).outerjoin(
        UserAlias, AdRequest.influencer_id == UserAlias.id
    ).filter(
        Campaign.sponsor_id == user.id,
        AdRequest.status.in_(['pending', 'active', 'rejected'])
    ).all()

    for ad_req, campaign, user_alias in ad_requests:
        if campaign.end_date < datetime.utcnow().date():
            ad_req.status = 'expired'
            db.session.commit()

    if request.method == 'POST':
        if 'create_public' in request.form:
            return redirect(url_for('create_public_ad_request'))
        elif 'create_private' in request.form:
            return redirect(url_for('create_private_ad_request'))

    completed_ad_requests = db.session.query(AdRequest, Campaign, UserAlias).select_from(
    AdRequest
    ).join(
    Campaign, AdRequest.campaign_id == Campaign.id
    ).outerjoin(
    UserAlias, AdRequest.influencer_id == UserAlias.id
    ).filter(
    AdRequest.status == 'complete'
    ).all()

    expired_ad_requests = db.session.query(AdRequest, Campaign, UserAlias).select_from(
        AdRequest
    ).join(
        Campaign, AdRequest.campaign_id == Campaign.id
    ).outerjoin(
        UserAlias, AdRequest.influencer_id == UserAlias.id
    ).filter(
        AdRequest.status == 'expired'
    ).all()

    return render_template('sponsor_ad_request.html', ad_requests=ad_requests, completed_ad_requests=completed_ad_requests, created_ad_requests=created_ad_requests, expired_ad_requests=expired_ad_requests)


@app.route('/create_public_ad_request', methods=['GET', 'POST'])
def create_public_ad_request():
    if request.method == 'POST':
        
        campaign_id = request.form.get('campaign_id')
        requirements = request.form.get('requirements')
        payment_amount = request.form.get('payment_amount')

        
        if not campaign_id or not requirements or not payment_amount:
            flash('All fields are required.', 'error')
            return redirect(url_for('create_public_ad_request'))

       
        new_ad_request = AdRequest(
            campaign_id=campaign_id,
            requirements=requirements,
            payment_amount=payment_amount,
            status='created'  
        )

        try:
            db.session.add(new_ad_request)
            db.session.commit()
            flash('Public Ad request created successfully!', 'success')
            return redirect(url_for('sponsor_ad_request'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating ad request. Please try again.', 'error')
            return redirect(url_for('create_public_ad_request'))

    public_campaigns = Campaign.query.filter(
        Campaign.visibility == 'public',
        Campaign.end_date >= datetime.utcnow().date()
    ).all()

    return render_template('create_public_ad_request.html', public_campaigns=public_campaigns)


@app.route('/create_private_ad_request', methods=['GET', 'POST'])
def create_private_ad_request():
    if request.method == 'POST':
        
        campaign_id = request.form.get('campaign_id')
        influencer_id = request.form.get('influencer_id')
        requirements = request.form.get('requirements')
        payment_amount = request.form.get('payment_amount')

        
        if not campaign_id or not influencer_id or not requirements or not payment_amount:
            flash('All fields are required.', 'error')
            return redirect(url_for('create_private_ad_request'))

        new_ad_request = AdRequest(
            campaign_id=campaign_id,
            influencer_id=influencer_id,
            requirements=requirements,
            payment_amount=payment_amount,
            status='pending' 
        )

        try:
            db.session.add(new_ad_request)
            db.session.commit()
            flash('Private Ad request created successfully!', 'success')
            return redirect(url_for('sponsor_ad_request'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating ad request. Please try again.', 'error')
            return redirect(url_for('create_private_ad_request'))
            
    private_campaigns = Campaign.query.filter(
        Campaign.visibility == 'private',
        Campaign.end_date >= datetime.utcnow().date()
    ).all()
    influencers = User.query.filter_by(role='influencer').all()

    return render_template('create_private_ad_request.html', private_campaigns=private_campaigns, influencers=influencers)


@app.route('/sponsor_edit_ad_request/<int:ad_request_id>', methods=['GET', 'POST'])
def edit_ad_request(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)

    if ad_request.status == 'active':
        flash('You cannot edit an active ad request.', 'info')
        return redirect(url_for('sponsor_ad_request'))

    if request.method == 'POST':
        ad_request.requirements = request.form.get('requirements')
        ad_request.payment_amount = request.form.get('payment_amount')

        db.session.commit()
        flash('Ad Request updated successfully!', 'success')
        return redirect(url_for('sponsor_ad_request'))

    return render_template('sponsor_edit_ad_request.html', ad_request=ad_request)

@app.route('/delete_ad_request/<int:ad_request_id>', methods=['POST'])
def delete_ad_request(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)

    if ad_request.status == 'active':
        flash('You cannot delete an active ad request.', 'info')
        return redirect(url_for('sponsor_ad_request'))
    
    db.session.delete(ad_request)
    db.session.commit()
    flash('Ad Request deleted successfully!', 'success')
    return redirect(url_for('sponsor_ad_request'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_role', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == "__main__": 
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=True)







