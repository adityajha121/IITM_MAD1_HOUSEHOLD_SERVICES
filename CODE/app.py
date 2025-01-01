
from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_sqlalchemy import SQLAlchemy 
from sqlalchemy.exc import IntegrityError
import datetime
import json
from sqlalchemy.orm import aliased
from sqlalchemy.orm import joinedload


import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
plt.switch_backend('agg')
import seaborn as sns
import pandas as pd
import os
import io
import base64
from sqlalchemy import text
from flask_migrate import Migrate
import random
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from datetime import datetime
now = datetime.now()
from flask import jsonify
from sqlalchemy import func
from flask_login import LoginManager, UserMixin, current_user, login_user, login_required, logout_user
from paytmchecksum import generateSignature
from paytmchecksum import verifySignature


app= Flask(__name__, static_folder='static')


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'instances', 'household_services.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

app.config['SECRET_KEY']='Har Har Mahadev'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_PERMANENT'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'aadityajha675@gmail.com'
app.config['MAIL_PASSWORD'] = 'lwon poiy iswh tqsj'
mail = Mail(app)

app.app_context().push()
login_manager=LoginManager()
login_manager.init_app(app)
#db.engine.execute('ALTER TABLE X ADD COLUMN X INTEGER')

@login_manager.user_loader
def load_user(user_id):
    
    return Customer.query.get(int(user_id))

  
def load_user(user_id):
    return ServiceProviders.query.get(int(user_id))
 
 
 









#i am making data_models from here

#for user
class User_otp(db.Model): 
    __tablename__ = 'User_otp'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp = db.Column(db.String(6), nullable=True)  
    otp_expiration = db.Column(db.DateTime, nullable=True)



#for customers model

class Customer(db.Model,UserMixin):
    __tablename__ = "customers"  
    id = db.Column(db.Integer, primary_key=True)
    User_fname = db.Column(db.String, nullable=False)
    User_lname = db.Column(db.String, nullable=False)
    
    User_email = db.Column(db.String, unique=True, nullable=False)
    User_mobile = db.Column(db.String, unique=True, nullable=False)
    
    Country_code_id = db.Column(db.Integer, nullable=False)
    User_uname = db.Column(db.String, nullable=False, unique=True)
    
    User_password = db.Column(db.String(15), unique=False, nullable=False)
    address = db.Column(db.String, nullable=False)

    User_pincode = db.Column(db.String(6), nullable=False)
    User_state = db.Column(db.String(20), nullable=False)
    User_city = db.Column(db.String(20), nullable=False)
    is_active = db.Column(db.Boolean, default=True) 


#for services model
class Service(db.Model,UserMixin):
    __tablename__ = 'services'
    
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(100), nullable=False) 
    time_required_for_service = db.Column(db.String(50), nullable=False)
    date_created = db.Column(db.DateTime, default=db.func.now())
    service_description = db.Column(db.String(255), nullable=False)
    service_base_price = db.Column(db.Float, nullable=False)
    
    service_requests = db.relationship('ServiceRequest', backref='service', lazy=True)
    created_by_admin = db.Column(db.Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<Service {self.service_name}>'


#for servicerequets modal
class ServiceRequest(db.Model,UserMixin):
    __tablename__ = 'service_requests'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False) 
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False) 
    professional_id = db.Column(db.Integer, db.ForeignKey('service_providers.id'), nullable=True) 

    time_of_service_request = db.Column(db.DateTime, default=db.func.now()) 
    time_of_service_completion = db.Column(db.DateTime, nullable=True)
    service_status = db.Column(db.String(50), nullable=False, default='requested')
    remarks_on_service = db.Column(db.String(255), nullable=True)
    Service_cancelation = db.Column(db.DateTime, nullable=True)
    customer = db.relationship('Customer', backref='service_requests', lazy=True)
    service_providers=db.relationship('ServiceProviders',backref='service_requests',lazy=True)
    def __repr__(self):
        return f'<ServiceRequest {self.id} - {self.service.service_name}>'

#service_providers model
class ServiceProviders(db.Model, UserMixin):
    __tablename__ = 'service_providers'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    provider_name = db.Column(db.String, nullable=False)
    email_id = db.Column(db.String, unique=True, nullable=False)
    phone_number = db.Column(db.String, nullable=False)
    provider_passwod=db.Column(db.String, nullable=False)
    provider_address=db.Column(db.String, nullable=False)
    provider_pincode = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    experience = db.Column(db.Integer, nullable=True)
    service_type = db.Column(db.String, nullable=False)
    base_price=db.Column(db.Float, nullable=False, default=0.0)
    is_active = db.Column(db.Boolean, default=True)
    service_requests_as_provider = db.relationship('ServiceRequest', backref='professional', lazy=True)
    approved = db.Column(db.Boolean, default=False) 


    
    def get_id(self):
        return str(self.id)
    
    def __repr__(self):
        return f'<ServiceProvider {self.provider_name}>'
#review model
class review(db.Model,UserMixin):
    __tablename__ = 'reviews'
    
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    review_text = db.Column(db.String(255), nullable=True)
    review_date = db.Column(db.DateTime, default=db.func.now())
    provider_id = db.Column(db.Integer, db.ForeignKey('service_providers.id'))
    
    customer = db.relationship('Customer', backref='reviews', lazy=True)
    service = db.relationship('Service', backref='reviews', lazy=True)

    def __repr__(self):
        return f'<Review {self.id} - {self.service.service_name} by {self.customer.User_fname}>'



#chat model
class Chat(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    service_request_id = db.Column(db.Integer, db.ForeignKey('service_requests.id'), nullable=False)
    sender_id = db.Column(db.Integer, nullable=False)  
    recipient_id = db.Column(db.Integer, nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())

    service_request = db.relationship('ServiceRequest', backref='messages')

    sender_customer = db.relationship(
        'Customer', 
        foreign_keys=[sender_id], 
        primaryjoin="and_(Chat.sender_id==Customer.id, Customer.id==Chat.sender_id)", 
        backref='sent_messages', 
        uselist=False
    )
    
    sender_provider = db.relationship(
        'ServiceProviders', 
        foreign_keys=[sender_id], 
        primaryjoin="and_(Chat.sender_id==ServiceProviders.id, ServiceProviders.id==Chat.sender_id)", 
        backref='sent_messages_as_provider', 
        uselist=False
    )
    recipient_customer = db.relationship(
        'Customer', 
        foreign_keys=[recipient_id], 
        primaryjoin="and_(Chat.recipient_id==Customer.id, Customer.id==Chat.recipient_id)", 
        backref='received_messages', 
        uselist=False
    )
    
    recipient_provider = db.relationship(
        'ServiceProviders', 
        foreign_keys=[recipient_id], 
        primaryjoin="and_(Chat.recipient_id==ServiceProviders.id, ServiceProviders.id==Chat.recipient_id)", 
        backref='received_messages_as_provider', 
        uselist=False
    )

    @property
    def sender(self):
        if self.sender_customer:
            return self.sender_customer
        return self.sender_provider

    @property
    def recipient(self):
        if self.recipient_customer:
            return self.recipient_customer
        return self.recipient_provider






#payments model
class Payments(db.Model):
    __tablename__ = "payments"
    
    id = db.Column(db.Integer, primary_key=True)
    service_request_id = db.Column(db.Integer, db.ForeignKey('service_requests.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')
    transaction_id = db.Column(db.String(100), nullable=True)
    payment_gateway = db.Column(db.String(50), nullable=False, default='Paytm')
    created_at = db.Column(db.DateTime, default=db.func.now())

    service_request = db.relationship('ServiceRequest', backref='payments')






with app.app_context():
    db.create_all()

#from here i am making app.py file

@app.route('/', methods=['GET'])
@login_required
def index():
    services = Service.query.all()
    pincode = request.args.get('pincode')
    service_type = request.args.get('service_type')
    max_price = request.args.get('base_price')
   

    query = ServiceProviders.query

    if pincode:
        query = query.filter(ServiceProviders.provider_pincode == pincode)
    if service_type:
        query = query.filter(ServiceProviders.service_type.ilike(f"%{service_type}%"))
    if max_price:
        try:
            max_price = float(max_price)
            query = query.filter(ServiceProviders.base_price <= max_price)
        except ValueError:
            pass
    service_providers = query.all()

    return render_template('index.html', service_providers=service_providers, services=services)

 
 
@app.route('/services/<string:service_name>')
def filter_services(service_name):
    services = Service.query.filter_by(service_name=service_name).all()
    return render_template('filtered_services.html', services=services, service_name=service_name)

 
 
 
#to view service providers

@app.route('/service_providers/<string:service_name>')
def view_service_providerss(service_name):
    providers = ServiceProviders.query.filter_by(service_type=service_name).all()
    return render_template('service_providers.html', providers=providers, service_name=service_name)


#for service details

@app.route('/services/<service_name>', methods=['GET'])
def service_detail(service_name):
    service = Service.query.filter_by(service_name=service_name).first_or_404()

    service_providers = ServiceProviders.query.filter_by(service_type=service_name, approved=True).all()
    
    return render_template('service_detail.html', service=service, service_providers=service_providers)






    
        






#to generate otp
 
def generate_otp(self):
    self.otp = str(random.randint(100000, 999999))  
    self.otp_expiration = datetime.utcnow() + timedelta(minutes=3) 
    db.session.commit() 
    return self.otp


#if customers forgots his password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = Customer.query.filter_by(User_email=email).first()  
        
        if not user:
            flash('Email_id not found.')
            return redirect('/forgot_password')

        
        user_otp = User_otp.query.filter_by(User_email=email).first()
        if not user_otp:
            user_otp = User_otp(email=user.email, password='ANY_password')
            db.session.add(user_otp)

        otp = user_otp.generate_otp() 
        
        
        msg = Message("Your OTP for Password Reset", sender="aadityajha675@gmail.com", recipients=[user.email])
        msg.body = f"Your OTP for password reset is {otp}. It is valid for only 3 minutes."
        mail.send(msg)

        flash('OTP has been sent to your email. Please check your inbox!!!!.')
        db.session.commit()  
        return redirect('/verify_otp')  
    
    return render_template('forgot_password.html')




#for ORTP verification
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        email = request.form['email']
        otp = request.form['otp']
        
        user = User_otp.query.filter_by(email=email).first()
        
        if not User_otp:
            flash('Invalid email.')
            return redirect('/verify_otp')

        
        if User_otp.otp is None or user.otp != otp or datetime.utcnow() > user.otp_expiration:
            flash('Invalid or expired OTP.')
            return redirect('/verify_otp')

        
        flash('OTP verified. You can now reset your password.')
        return redirect('/reset_password')
    
    return render_template('verify_otp.html')


#for reseting the password
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        new_password = request.form['password']

        user_otp_entry = User_otp.query.filter_by(email=email).first()
        
        if not user_otp_entry:
            flash('Invalid email.')
            return redirect('/reset_password')

    
        user_otp_entry.password = new_password
        user_otp_entry.otp = None  
        user_otp_entry.otp_expiration = None 
        db.session.commit()

        flash('Password reset successful! You can now log in.')
        return redirect('/login')
    
    return render_template('reset_password.html')




#for customer to register
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method=="POST":
        email = request.form.get('email_id')
       
        username=request.form.get('user_name')
       
        fname=request.form.get('first_name')
       
        lname=request.form.get('last_name')
       
        password=request.form.get('customer_password')
       
        mobile_number=request.form.get('mobile_NUMBER')
       
        pincode=request.form.get('customer_pincode')
       
        address1=request.form.get('customer_address')
       
        state=request.form.get('state')
       
        city=request.form.get('city')
       
        country_code_id=request.form.get('country_id')
        
        customer=Customer(User_uname=username, User_email=email, User_fname=fname, User_lname=lname, User_password=password, User_mobile=mobile_number, address=address1, User_pincode=pincode, User_state=state, Country_code_id= country_code_id, User_city=city)
        customer_in_db = Customer.query.filter(
            (Customer.User_email == email) or(Customer.User_uname == username) or
            (Customer.User_mobile == mobile_number) ).first()

        if customer_in_db:
            flash('Email, Username, or Mobile Number already exists. Please try again.')
            return redirect('/register')
        else:
            db.session.add(customer)
            db.session.commit()
            flash("user has been registered successfully", "success")
            return redirect('/login')
    return render_template("register.html") 



#for service providers registeration
    
@app.route("/services_provider_registeration", methods=['GET', 'POST'])
def services_provider_registeration():
    if request.method == 'POST':
        provider_name = request.form.get('Serviceprovider_name')
        email_id = request.form.get('Provider_email_id')
        provider_passwod = request.form.get('serviceprovider_password')
        service_type = request.form.get('service_type')
        phone_number = request.form.get('phone_number')
        description = request.form.get('provider_description')
        provider_address = request.form.get('provider_address')
        provider_experience = request.form.get('experience')
        provider_pincode = request.form.get('provider_pincode')
        base_price = request.form.get('base_price')

        if not provider_name or not email_id or not provider_passwod:
            flash('Please fill in all required fields', 'warning')
            return redirect(url_for('service_provider_login'))

        already_provider = ServiceProviders.query.filter(
            (ServiceProviders.email_id == email_id) | (ServiceProviders.phone_number == phone_number)).first()

        if already_provider:
            flash('Email or phone number already exists. Please try again.', 'warning')
            return redirect(url_for('services_provider_registeration'))
        new_serviceprovider = ServiceProviders(provider_name=provider_name,email_id=email_id,provider_passwod=provider_passwod, provider_pincode=provider_pincode,service_type=service_type,phone_number=phone_number,experience=provider_experience, 
            description=description,provider_address=provider_address,base_price=base_price)
        try:
            db.session.add(new_serviceprovider)
            db.session.commit()
            flash("You have been registered successfully", "success")
            return redirect(url_for('service_provider_login'))
        except IntegrityError as e:
            db.session.rollback()  
            flash('A provider with this email or phone number already exists.', 'danger')
    return render_template("services_provider_registeration.html")



#for customers to ligin

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['customer_email_id']
        password = request.form['customer_password']

        customer = Customer.query.filter_by(User_email=email).first()
        if customer:
            if not customer.is_active:
                flash('Your account has been blocked. Please contact Admin aadityajha44@gmail.com.', 'danger')
                return redirect(url_for('login'))

            if customer.User_password == password:
                login_user(customer)
                session['user_id'] = customer.id
                flash('Login successful!', 'success')

                if customer.id == 1:
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('index'))
    return render_template('login.html')


#for customer to veiw their profiles

@app.route('/View_profile', methods=['GET', 'POST'])
@login_required

def View_profile():
   
   customer = Customer.query.filter_by(id=current_user.id).first()
    
   if request.method == 'POST':
        customer.User_fname = request.form['User_fname']
        customer.User_lname = request.form['User_lname']
        customer.User_email = request.form['User_email']
        customer.User_mobile = request.form['User_mobile']
        customer.address = request.form['address']
        customer.User_pincode = request.form['User_pincode']
        customer.User_state = request.form['User_state']
        customer.User_city = request.form['User_city']

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('index'))  

   return render_template('View_profile.html', customer=customer)


#for admin dashboard

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    
    if current_user.id != 1:
        flash("Access denied.", "danger")
        return redirect(url_for('login'))
    all_customers = Customer.query.all()
    all_providers = ServiceProviders.query.all()
    all_services = Service.query.all()
    if request.method == 'POST':
        if 'create_service' in request.form:
            service_name = request.form['service_name']
            time_required = request.form['time_required_for_service']
            description = request.form['service_description']
            base_price = float(request.form['service_base_price'])
            
            new_service = Service(service_name=service_name,time_required_for_service=time_required,service_description=description, service_base_price=base_price)
            db.session.add(new_service)
            db.session.commit()
            flash("New service created successfully.", "success")
            return redirect(url_for('admin_dashboard'))

    return render_template(
        'admin_dashboard.html',customers=all_customers,providers=all_providers,services=all_services )




@app.route('/approve_user/<int:user_id>')
@login_required
def approve_user(user_id):
    user = Customer.query.get_or_404(user_id) or ServiceProviders.query.get_or_404(user_id)
    user.is_active = True
    db.session.commit()
    flash('User approved successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


#for admin to block the user
@app.route('/block_user/<int:user_id>')
@login_required
def block_user(user_id):
    user = Customer.query.get_or_404(user_id) or ServiceProviders.query.get_or_404(user_id)
    user.is_active = False
    db.session.commit()
    flash('User blocked successfully.', 'danger')
    return redirect(url_for('admin_dashboard'))


#for admin to see the provider profile

@app.route('/Provider_profile')
def Provider_profile():
    if not current_user.is_authenticated or current_user.id != 1:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('index'))
    service_providers = ServiceProviders.query.all()
    return render_template('Provider_profile.html', service_providers=service_providers)



#for admin to approve the service

@app.route('/toggle_provider_approval/<int:provider_id>', methods=['POST'])
def toggle_provider_approval(provider_id):
    if not current_user.is_authenticated or current_user.id != 1:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('Provider_profile'))

    provider = ServiceProviders.query.get(provider_id)
    if provider:
        provider.approved = not provider.approved
        db.session.commit()
        status = "approved" if provider.approved else "disapproved"
        flash(f"Service provider {provider.provider_name} has been {status}.", "success")
    else:
        flash("Service provider not found.", "danger")

    return redirect(url_for('Provider_profile'))



#for admin to view the reject service providers


@app.route('/reject_provider/<int:provider_id>', methods=['POST'])
def reject_provider(provider_id):
    provider = ServiceProviders.query.get_or_404(provider_id)
    db.session.delete(provider)
    db.session.commit()
    flash(f"{provider.provider_name} has been rejected and removed from the system.", "danger")
    return redirect(url_for('admin_dashboard'))




#for admin to block the service providers

@app.route('/toggle_block_provider/<int:provider_id>', methods=['POST'])
def toggle_block_provider(provider_id):
    provider = ServiceProviders.query.get_or_404(provider_id)
    provider.is_active = not provider.is_active
    db.session.commit()
    action = "unblocked" if provider.is_active else "blocked"
    flash(f"{provider.provider_name} has been {action}.", "warning" if action == "blocked" else "success")
    return redirect(url_for('admin_dashboard'))




#for admin to block the customers
@app.route('/block_customer/<int:customer_id>', methods=['POST'])
def block_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    customer.is_active = not customer.is_active 
    db.session.commit()
    flash('Customer status updated successfully!', 'success')
    return redirect(url_for('view_customers'))





#for admin to see all the service providers whether approved or unapproved

@app.route('/view_service_providers', methods=['GET', 'POST'])
@login_required
def view_service_providers():
    search_query = request.form.get('search_query', '').strip()

    query = db.session.query(ServiceProviders)
    if search_query:
        query = query.filter(
            (ServiceProviders.provider_name.ilike(f"%{search_query}%")) |(ServiceProviders.email_id.ilike(f"%{search_query}%")) |
            (ServiceProviders.service_type.ilike(f"%{search_query}%")) )

    service_providers = query.all()

    return render_template('provider_profile.html',service_providers=service_providers,search_query=search_query)




#for admin to view the list of all the customers

@app.route('/view_customers')
def view_customers():
    
    customers = Customer.query.all()
    return render_template('view_customers.html', customers=customers)










#for admins to see the approved service providers

@app.route('/approved_providers', methods=['GET', 'POST'])
def approved_providers():
    search_query = request.form.get('search_query', '').strip()
    query = db.session.query(ServiceProviders)
    if search_query:
        query = query.filter(
            (ServiceProviders.provider_name.ilike(f"%{search_query}%")) |(ServiceProviders.email_id.ilike(f"%{search_query}%")) |
            (ServiceProviders.service_type.ilike(f"%{search_query}%")) )
    providers = query.all()
    providers = db.session.query(
        ServiceProviders,
        func.coalesce(func.avg(review.rating), 0).label('average_rating')).outerjoin(review, review.provider_id == ServiceProviders.id).filter(ServiceProviders.approved == True).group_by(ServiceProviders.id).all()
    return render_template('approved_providers.html', service_providers=providers,search_query=search_query)














#for admin to see the new services providers who have registered

@app.route('/view_service_provider_requests')
def view_service_provider_requests():
    pending_providers = ServiceProviders.query.filter_by(is_active=False).all()
    return render_template('provider_profile.html', providers=pending_providers)






#for admin to see the services created by him on his dashboard

@app.route('/admin_services')
def admin_services():
    admin_services = Service.query.filter_by(created_by_admin=True).all()
    return render_template('admin_DB.html', admin_services=admin_services)


#for admin to create the service

#for admin to edit the service created by him
@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)
    if request.method == 'POST':
        service.service_name = request.form['service_name']
        service.service_description = request.form['service_description']
        service.service_base_price = request.form['service_base_price']
        service.time_required_for_service = request.form['time_required_for_service']
        db.session.commit()
        flash('Service updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_service.html', service=service)



#for admin to delete the service



@app.route('/create_service', methods=['GET', 'POST'])
def create_service():
    if request.method == 'POST':
        service_name = request.form['service_name']
        service_description = request.form['service_description']
        service_base_price = request.form['service_base_price']
        time_required_for_service = request.form['time_required_for_service']

        new_service = Service(service_name=service_name, 
                              service_description=service_description,
                              service_base_price=service_base_price, 
                              time_required_for_service=time_required_for_service)

        db.session.add(new_service)
        db.session.commit()

        flash('New service created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_service.html')  






@app.route('/delete_service/<int:service_id>', methods=['POST'])
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    db.session.commit()
    flash("Service deleted successfully", "success")
    return redirect(url_for('admin_dashboard'))







#for admin to see the ongoing servie requests with their current status

@app.route('/admin/service-requestsss')
@login_required
def admin_service_requests():
    all_service_requests = ServiceRequest.query.all()
    
    completed_service_requests = ServiceRequest.query.filter_by(service_status='completed').all()

    return render_template('admin_service_requestss.html',all_service_requests=all_service_requests,completed_service_requests=completed_service_requests)













#for admin to see the completed service requests

@app.route('/admin/completed_service_requests', methods=['GET'])
def view_completed_service_requests():
    if not current_user.is_authenticated or current_user.id != 1:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('index'))
    completed_requests = ServiceRequest.query.filter(
        (ServiceRequest.service_status == 'completed') |(ServiceRequest.service_status == 'closed')).all()

    return render_template('admin_completed_service_requests.html',service_requests=completed_requests,title="Completed Service Requests")












































@app.route('/notifications')
def notifications():
    return("hellow Sir")







#for logging out customer and srvicce providers

@app.route('/logout')
def logout():
    session.clear()
    flash('You have logged out successfully.', 'info')
    return redirect(url_for('login'))

def active_requests():
    requests = ServiceRequest.query.filter_by(customer_id=current_user.id).all()
    
    active_requests = {request.service_id: request.service_status for request in requests}
    return active_requests
   

#for providers to see the servie requestss


@app.route('/view_requests', methods=['GET', 'POST'])
@login_required

def view_requests():
    search_query = request.form.get('search_query', '').strip()

    query = (
        db.session.query(ServiceRequest)
        .options( joinedload(ServiceRequest.customer), joinedload(ServiceRequest.service_providers),).filter_by(professional_id=current_user.id))
    if search_query:
        query = query.filter(
            (ServiceRequest.customer.has(Customer.User_fname.ilike(f"%{search_query}%"))) | (ServiceRequest.customer.has(Customer.User_lname.ilike(f"%{search_query}%"))) |(ServiceRequest.customer.has(Customer.User_pincode.ilike(f"%{search_query}%"))))
    requests = query.all()

    reviews = (db.session.query(review).filter_by(provider_id=current_user.id).all() )

   
    review_dict = {(rev.customer_id, rev.service_id): rev for rev in reviews }

    return render_template( 'view_requests.html', requests=requests, review_dict=review_dict, search_query=search_query )



#for professionals


@app.route('/view_requests<int:request_id>/accept', methods=['POST'])
@login_required
def accept_service_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    
    if service_request.professional_id != current_user.id:
        return redirect(url_for('view_requests'))
    service_request.service_status = 'accepted'
    db.session.commit()

    return redirect(url_for('view_requests'))

#for professionals to reject the service requests

@app.route('/view_requests/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_service_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    
    if service_request.professional_id != current_user.id:
        return redirect(url_for('view_requests'))

    service_request.service_status = 'rejected'
    db.session.commit()

    return redirect(url_for('view_requests'))

@app.route('/accept_request/<int:request_id>', methods=['POST'])
@login_required
def accept_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.professional_id == current_user.id:
        service_request.service_status = 'accepted'
        db.session.commit()
        flash("Request accepted successfully!", "success")
    else:
        flash("You cannot accept this request.", "error")
    return redirect(url_for('view_requests'))


#for professionals to reject the requests by customers

@app.route('/reject_request/<int:request_id>', methods=['POST'])
@login_required
def reject_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.professional_id == current_user.id:
        service_request.service_status = 'rejected'
        db.session.commit()
        flash("Request rejected successfully!", "warning")
    else:
        flash("You cannot reject this request.", "error")
    return redirect(url_for('view_requests'))



#for customers to complete request

@app.route('/complete_request/<int:request_id>', methods=['POST'])
@login_required
def complete_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.professional_id == current_user.id:
        service_request.service_status = 'completed'
        service_request.time_of_service_completion = db.func.now()
        db.session.commit()
        flash("Service completed successfully!", "success")
    else:
        flash("You cannot complete this request.", "error")
    
    return redirect(url_for('view_requests'))

@app.route('/service_professional_dashboard')
def service_professional_dashboard():
    return render_template("service_professional_dashboard.html")


#for professionals to login

@app.route("/service_provider_login", methods=['GET', 'POST'])
def service_provider_login():
    if request.method == 'POST':
        email_id = request.form.get('email')  
        password = request.form.get('password')
        
        service_provider = ServiceProviders.query.filter_by(email_id=email_id).first()
        
        if service_provider:
            if not service_provider.is_active:
                flash('Your account has been blocked. Please contact the Admin at Aadityakumarjha44@gmail.com.', 'danger')
                return redirect(url_for('service_provider_login')) 
            
            if service_provider.provider_passwod == password:
                login_user(service_provider)
                
                flash('Login successful!', 'success')
                return redirect(url_for('view_requests'))
            
            else:
                flash('Invalid login credentials. Please try again.', 'danger')
        
        else:
            flash('Service provider with this email does not exist.', 'danger')
    
    return render_template('service_provider_login.html')

    
        
    
        
        
        
        
        
        
        
        
        
        
        

    






#for customers to see the booked services

@app.route('/booked_services')
@login_required  
def booked_services():
     
     
     
     
     
     
     
     
    

    
     accepted_requests = ServiceRequest.query.filter_by(customer_id=current_user.id, service_status='accepted').all()
     rejected_requests = ServiceRequest.query.filter_by(customer_id=current_user.id, service_status='rejected').all()
     return render_template('booked_service.html', accepted_requests=accepted_requests, rejected_requests=rejected_requests)


#for customers to send the service requests

@app.route('/send_request/<int:provider_id>', methods=['POST'])
def send_request(provider_id):
    service_id = request.form.get('service_id') 
    service_provider = ServiceProviders.query.get(provider_id)

    if not service_provider or not service_provider.approved:
        flash("Service provider is not available or not approved.", "danger")
        return redirect(url_for('Services'))
    existing_request = ServiceRequest.query.filter_by(customer_id=current_user.id,service_id=service_id,professional_id=provider_id,service_status='requested').first()
    if existing_request:
        flash("You already have an active request for this service provider.", "warning")
        return redirect(url_for('Services'))
    new_request = ServiceRequest(service_id=service_id,customer_id=current_user.id,professional_id=provider_id,service_status='requested')
    db.session.add(new_request)
    db.session.commit()
    flash("Service request sent successfully.", "success")
    return redirect(url_for('Services'))




#for customers to cancle the service request

@app.route('/cancel_request/<int:request_id>', methods=['POST'])
def cancel_request(request_id):
    service_request = ServiceRequest.query.get(request_id)
    if not service_request or service_request.customer_id != current_user.id:
        flash("Invalid service request.", "danger")
        return redirect(url_for('Services'))

    if service_request.service_status != 'requested':
        flash("You can only cancel requests that are still pending.", "warning")
        return redirect(url_for('Services'))
    service_request.service_status = 'canceled'
    service_request.Service_cancelation = db.func.now()
    db.session.commit()
    flash("Service request canceled successfully.", "success")
    return redirect(url_for('Services'))



#for customer to close the service request after completion of service


@app.route('/close_service/<int:request_id>', methods=['POST'])
def close_service(request_id):
    service_request = ServiceRequest.query.get(request_id)
    if not service_request or service_request.customer_id != current_user.id:
        flash("Invalid service request.", "danger")
        return redirect(url_for('Services'))   
    service_request.service_status = 'closed'
    db.session.commit()

    flash("Service has been successfully closed. You can now post a review.", "success")
    return redirect(url_for('Services'))










#for customers to see the list of service providers with their average ratingd

@app.route('/Services')
def Services():
    service_providers = ServiceProviders.query.all()
    provider_ratings={}

    for provider in service_providers:
        reviews = review.query.filter_by(provider_id=provider.id).all()

        if reviews:
            total_rating = sum(rating.rating for rating in reviews)
            average_rating = total_rating / len(reviews)
            provider_ratings[provider.id] = round(average_rating, 2)
        else:
            provider_ratings[provider.id] = 0
    return render_template('Services.html', service_providers=service_providers, provider_ratings=provider_ratings)























 #for admin to see the approved service provider with their avg ratings

@app.route('/service_providers', methods=['GET', 'POST'])
def service_providers():
    search_query = request.args.get('search_query', '')
    service_provider_alias = aliased(ServiceProviders)

    query = db.session.query(ServiceProviders).filter(
        (ServiceProviders.provider_name.ilike(f'%{search_query}%')) |(ServiceProviders.service_type.ilike(f'%{search_query}%')))
    service_providers = query.all()

    provider_ratings = {}
    for provider in service_providers:
        ratings = db.session.query(review).filter_by(provider_id=provider.id).all()
        if ratings:
            avg_rating = sum([r.rating for r in ratings]) / len(ratings)
            provider_ratings[provider.id] = avg_rating
        else:
            provider_ratings[provider.id] = 0 

    return render_template('service_providers.html', service_providers=service_providers,provider_ratings=provider_ratings, search_query=search_query)


#for searching of serviceproviders

@app.route('/search_service_providers', methods=['GET'])
def search_service_providers():
    search_query = request.args.get('search_query', ' ')
    query = ServiceProviders.query.filter(ServiceProviders.approved == True)

    if search_query:
        query = query.filter(
            (ServiceProviders.provider_name.ilike(f'%{search_query}%')) |(ServiceProviders.service_type.ilike(f'%{search_query}%')) |
            (ServiceProviders.provider_pincode.ilike(f'%{search_query}%'))
        )
    providers = query.all()
    no_results = len(providers) == 0
    return render_template('service_providers.html', providers=providers,search_query=search_query, no_results=no_results)









 
 
 
 
 

 
 

























@app.route('/admin/assign-service/<int:request_id>/assign', methods=['GET', 'POST'])
def assign_service_to_professional(request_id):
    if not current_user.is_authenticated or current_user.id != 1:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))
    service_request = ServiceRequest.query.get_or_404(request_id)
    
    if service_request.professional_id is not None:
        flash("This service request is already assigned.", "info")
        return redirect(url_for('unassigned_service_requests'))
    professionals = ServiceProviders.query.filter_by(
        service_type=service_request.service.service_name, approved=True, is_active=True
    ).all()

    if request.method == 'POST':
        professional_id = request.form.get('professional_id')
        selected_professional = ServiceProviders.query.get_or_404(professional_id)
    
        service_request.professional_id = selected_professional.id
        service_request.service_status = 'assigned'
        db.session.commit()
        
        flash(f"Service request {request_id} has been assigned to {selected_professional.provider_name}.", "success")
        return redirect(url_for('unassigned_service_requests'))

    return render_template('assign_service.html', service_request=service_request, professionals=professionals)



























@app.route('/admin/service-requests')
def unassigned_service_requests():
    if not current_user.is_authenticated or current_user.id != 1:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))
    
    requests = ServiceRequest.query.filter_by(professional_id=None, service_status='requested').all()
    return render_template('admin_service_requests.html', requests=requests)

#for chat between customers and serviceproviders









@app.route('/chat/<int:service_request_id>', methods=['GET', 'POST'])
@login_required
def chat(service_request_id):
    service_request = ServiceRequest.query.get_or_404(service_request_id)
    messages = Chat.query.filter_by(service_request_id=service_request_id).order_by(Chat.timestamp).all()

    if request.method == 'POST':
        message_text = request.form['message']
        new_message = Chat(
            service_request_id=service_request_id,
            sender_id=current_user.id,  # Assuming current_user.id is either customer or provider ID
            recipient_id=service_request.customer_id if current_user.id != service_request.customer_id else service_request.professional_id,
            message=message_text
        )
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent successfully!', 'success')
        return redirect(url_for('chat', service_request_id=service_request_id))

    return render_template('chat.html', service_request=service_request, messages=messages)




















#for review by customer
@app.route('/post_review/<int:request_id>', methods=['POST'])
def post_review(request_id):
    service_request = ServiceRequest.query.get(request_id)
    if not service_request or service_request.customer_id != current_user.id:
        flash("Invalid service request.", "danger")
        return redirect(url_for('Services'))
    if service_request.service_status != 'closed':
        flash("You can only post a review after the service is closed.", "warning")
        return redirect(url_for('Services'))
    rating = request.form.get('rating')
    review_text = request.form.get('review_text')
    if not rating or not review_text:
        flash("Please provide both a rating and review text.", "danger")
        return redirect(url_for('Services'))
    new_review = review(service_id=service_request.service_id,customer_id=service_request.customer_id,provider_id=service_request.professional_id,rating=rating,review_text=review_text)

    db.session.add(new_review)
    db.session.commit()
    flash("Review posted successfully.", "success")
    return redirect(url_for('Services'))

#cutomer bookings
@app.route('/my-booked-services')
def my_booked_services():
    if not current_user.is_authenticated:
        flash('You need to log in first', 'danger')
        return redirect(url_for('login'))
    accepted_requests = ServiceRequest.query.filter_by(customer_id=current_user.id, service_status='accepted').all()
    rejected_requests = ServiceRequest.query.filter_by(customer_id=current_user.id, service_status='rejected').all()
    return render_template('my_booked_services.html', accepted_requests=accepted_requests, rejected_requests=rejected_requests)

#for admin summary and reports

@app.route('/summary', methods=['GET'])
def admin_summary():
    chart_dir = os.path.join(os.getcwd(), 'static', 'charts')
    if not os.path.exists(chart_dir):
        os.makedirs(chart_dir)
    requests_by_date = db.session.query(func.date(ServiceRequest.time_of_service_request).label('date'),func.count(ServiceRequest.id).label('count')).group_by(func.date(ServiceRequest.time_of_service_request)).all()

    requests_by_service = db.session.query(
        Service.service_name,
        func.count(ServiceRequest.id).label('count')).join(ServiceRequest, Service.id == ServiceRequest.service_id).group_by(Service.id).all()

    requests_by_pincode = db.session.query(
        Customer.User_pincode,func.count(ServiceRequest.id).label('count')).join(ServiceRequest, Customer.id == ServiceRequest.customer_id).group_by(Customer.User_pincode).all()

    if requests_by_date:
        dates, counts = zip(*requests_by_date)
        plt.figure(figsize=(10, 5))
        sns.lineplot(x=dates, y=counts, marker='o')
        plt.title('Number of Requests by Date')
        plt.xlabel('Date')
        plt.ylabel('Number of Requests')
        plt.xticks(rotation=45)
        plt.tight_layout()
        chart1_path = os.path.join(chart_dir, 'requests_by_date.png')
        plt.savefig(chart1_path)
        plt.close()
    else:
        chart1_path = None

    if requests_by_service:
        services, service_counts = zip(*requests_by_service)
        plt.figure(figsize=(10, 5))
        sns.barplot(x=services, y=service_counts, palette='viridis')
        plt.title('Requests by Service')
        plt.xlabel('Service Type')
        plt.ylabel('Number of Requests')
        plt.xticks(rotation=45)
        plt.tight_layout()
        chart2_path = os.path.join(chart_dir, 'requests_by_service.png')
        plt.savefig(chart2_path)
        plt.close()
    else:
        chart2_path = None
    if requests_by_pincode:
        pincodes, pincode_counts = zip(*requests_by_pincode)
        plt.figure(figsize=(10, 5))
        sns.barplot(x=pincodes, y=pincode_counts, palette='coolwarm')
        plt.title('Requests by Pincode')
        plt.xlabel('Pincode')
        plt.ylabel('Number of Requests')
        plt.xticks(rotation=45)
        plt.tight_layout()
        chart3_path = os.path.join(chart_dir, 'requests_by_pincode.png')
        plt.savefig(chart3_path)
        plt.close()
    else:
        chart3_path = None
    most_demanded_service = max(requests_by_service, key=lambda x: x[1], default=('None', 0))
    return render_template(
        'summary.html',chart1_path=chart1_path,chart2_path=chart2_path,chart3_path=chart3_path,most_demanded_service=most_demanded_service)








@app.route('/Sp_profile', methods=['GET', 'POST'])
@login_required
def Sp_profile():
    service_provider = ServiceProviders.query.filter_by(id=current_user.id).first()

    if not service_provider:
        flash("Service provider not found!", "error")
        return redirect(url_for('index'))

    if request.method == 'POST':
        service_provider.provider_name = request.form['User_fname']  
        service_provider.email_id = request.form['User_email']  
        service_provider.phone_number = request.form['User_mobile']  
        service_provider.provider_address = request.form['address'] 
        service_provider.provider_pincode = request.form['User_pincode'] 
        service_provider.description = request.form['description'] 
        service_provider.experience = request.form['experience']
        db.session.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('view_requests'))

    return render_template('Sp_profile.html', service_provider=service_provider)





@app.route('/professional_summary', methods=['GET'])
@login_required
def professional_summary():
    professional = ServiceProviders.query.filter_by(id=current_user.id).first()
    if not professional:
        flash('Service provider not found!', 'danger')
        return redirect(url_for('index'))
    service_requests = ServiceRequest.query.filter_by(professional_id=professional.id).all()
   
    data = [
        {
            'Date': req.time_of_service_request.date(),
            'Pincode': req.customer.User_pincode if req.customer else None,}
        for req in service_requests]
    df = pd.DataFrame(data)
    img_date, img_pincode = generate_summary_plots(df)

    return render_template('professional_summary.html', professional=professional, img_date=img_date, img_pincode=img_pincode)



def generate_summary_plots(df):
    img_date, img_pincode = None, None
    if not df.empty:
        plt.figure(figsize=(10, 6))
        sns.countplot(data=df, x='Date', palette='viridis')
        plt.title('Service Requests by Date')
        plt.xticks(rotation=45)
        plt.tight_layout()
        img_date = encode_plot_to_base64()
        plt.figure(figsize=(10, 6))
        sns.countplot(data=df, x='Pincode', palette='coolwarm')
        plt.title('Service Requests by Pincode')
        plt.xticks(rotation=45)
        plt.tight_layout()
        img_pincode = encode_plot_to_base64()
    return img_date, img_pincode

















def encode_plot_to_base64():
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    buf.close()
    plt.close()
    return img_base64









@app.route('/customer_summary')
def customer_summary():
    customer_id = session.get('user_id')
    
    if not customer_id:
        flash('You must be logged in to view this page.', 'danger')
        return redirect(url_for('customer_login'))

    service_requests = ServiceRequest.query.filter_by(customer_id=customer_id).all()

    service_counts = db.session.query(
        Service.service_name,
        func.count(ServiceRequest.id)).join(ServiceRequest, ServiceRequest.service_id == Service.id)\
     .filter(ServiceRequest.customer_id == customer_id)\
     .group_by(Service.service_name).all()

    requests_by_date = db.session.query(
        func.date(ServiceRequest.time_of_service_request),
        func.count(ServiceRequest.id)).filter(ServiceRequest.customer_id == customer_id)\
     .group_by(func.date(ServiceRequest.time_of_service_request)).all()

    service_names = [s[0] for s in service_counts]
    service_counts_data = [s[1] for s in service_counts]
    request_dates = [
    datetime.strptime(r[0], '%Y-%m-%d').strftime('%Y-%m-%d') 
    if isinstance(r[0], str) else r[0].strftime('%Y-%m-%d')
    for r in requests_by_date
]
    
    request_counts = [r[1] for r in requests_by_date]

    plt.figure(figsize=(10, 5))
    sns.barplot(x=service_names, y=service_counts_data, palette='viridis')
    plt.title('Services Requested Most Frequently')
    plt.xlabel('Service Name')
    plt.ylabel('Request Count')
    plt.xticks(rotation=45)
    buf1 = io.BytesIO()
    plt.savefig(buf1, format='png')
    buf1.seek(0)
    service_counts_chart = base64.b64encode(buf1.getvalue()).decode('utf-8')
    plt.close()

    plt.figure(figsize=(10, 5))
    sns.lineplot(x=request_dates, y=request_counts, marker='o', color='blue')
    plt.title('Requests Over Time')
    plt.xlabel('Date')
    plt.ylabel('Number of Requests')
    plt.xticks(rotation=45)
    buf2 = io.BytesIO()
    plt.savefig(buf2, format='png')
    buf2.seek(0)
    requests_by_date_chart = base64.b64encode(buf2.getvalue()).decode('utf-8')
    plt.close()

    return render_template(
        'customer_summary.html',
        service_counts_chart=service_counts_chart,
        requests_by_date_chart=requests_by_date_chart
    )



      


    # plt.figure(figsize=(8, 8))
    # plt.pie(
        # service_counts_data,
        # labels=service_names,
        # autopct='%1.1f%%',
        # startangle=140,
        # colors=sns.color_palette('viridis', len(service_names))
    # )
    # plt.title('Service Requests Distribution by Service')
    # plt.tight_layout()
    # buf2 = io.BytesIO()
    # plt.savefig(buf2, format='png')
    # buf2.seek(0)
    # service_counts_pie_chart = base64.b64encode(buf2.getvalue()).decode('utf-8')
    # plt.close()

    
    # plt.figure(figsize=(8, 8))
    # plt.pie(
        # request_counts,
        # labels=request_dates,
        # autopct='%1.1f%%',
        # startangle=140,
        # colors=sns.color_palette('viridis', len(request_dates))
    # )
    # plt.title('Service Requests Distribution Over Time')
    # plt.tight_layout()
    # buf3 = io.BytesIO()
    # plt.savefig(buf3, format='png')
    # buf3.seek(0)
    # requests_by_date_chart = base64.b64encode(buf3.getvalue()).decode('utf-8')
    # plt.close()

    
    # return render_template(
        # 'customer_summary.html',
        # service_counts_chart=service_counts_chart,
        # service_counts_pie_chart=service_counts_pie_chart,
        # requests_by_date_chart=requests_by_date_chart
    # )




# plt.pie(service_counts_data, labels=service_names, autopct='%1.1f%%', colors=sns.color_palette('viridis', len(service_counts_data)))
# 
















if __name__=="__main__":
    app.run(port=3000,debug=True)








# 
# @app.route('/create_service', methods=['GET', 'POST'])
# def create_service():
    # if request.method == 'POST':
        # service_name = request.form['service_name']
        # service_description = request.form['service_description']
        # service_base_price = request.form['service_base_price']
        # time_required_for_service = request.form['time_required_for_service']
# 
        # new_service = Service(service_name=service_name,service_description=service_description,service_base_price=service_base_price,time_required_for_service=time_required_for_service)
# 
        # db.session.add(new_service)
        # db.session.commit()
# 
        # flash('New service created successfully!', 'success')
        # return redirect(url_for('admin_dashboard'))
    #  
# 

