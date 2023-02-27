import os
from flask import Flask, render_template, flash, Markup, redirect, url_for, \
    request, send_from_directory, send_file, make_response
from app import app, db, login, hcaptcha
from app.forms import ContactForm, EmailListForm, SignupForm, LoginForm, UserForm, \
    RequestPasswordResetForm, ResetPasswordForm, ItemForm
from flask_login import current_user, login_user, logout_user, login_required, login_url
from app.models import User, Item
from werkzeug.urls import url_parse
from datetime import datetime
from app.email import send_contact_email, send_verification_email, send_password_reset_email
from functools import wraps

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_viewed = datetime.utcnow()
        db.session.commit()

def dir_last_updated(folder):
    return str(max(os.path.getmtime(os.path.join(root_path, f))
                   for root_path, dirs, files in os.walk(folder)
                   for f in files))

admin_email = app.config['MAIL_USERNAME']

@app.context_processor
def inject_values():
    return dict(last_updated=dir_last_updated('app/static'))

def admin_required(f):
    @login_required
    @wraps(f)
    def wrap(*args, **kwargs):
        if current_user.is_admin:
            return f(*args, **kwargs)
        else:
            flash('You must have administrator privileges to access this page.', 'error')
            logout_user()
            return redirect(login_url('signin', next_url=request.url))
    return wrap


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    form = ContactForm()
    categories = Item.query.with_entities(Item.category).distinct()
    items = Item.query.order_by(Item.order).all()
    images = []
    for i in os.listdir('app/static/img'):
        images.append(i)
    if form.validate_on_submit():
        if hcaptcha.verify():
            pass
        else:
            flash('A computer has questioned your humanity. Please try again.', 'error')
            return redirect(url_for('home'))
        user = User(first_name=form.first_name.data, email=form.email.data, phone=form.phone.data)
        message = form.message.data
        subject = form.subject.data
        email_status = send_contact_email(user, message)
        if email_status == 200:
            flash('Please check ' + user.email + ' for a confirmation email. Thank you for reaching out!')
            return redirect(url_for('index', _anchor="home"))
        else:
            flash('Email failed to send, please contact ' + admin_email, 'error')
    return render_template('index.html', form=form, categories=categories, items=items, \
        images=images)





@app.route('/about')
def about():
    return render_template('about.html', title="About")


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if current_user.is_authenticated:
        flash('You are already signed in.')
        return redirect(url_for('start_page'))
    form = LoginForm()
    signup_form = SignupForm()
    return render_template('signin.html', title='Sign in', form=form, signup_form=signup_form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = LoginForm()
    signup_form = SignupForm()
    if signup_form.validate_on_submit():
        user = User(first_name=signup_form.first_name.data, last_name=signup_form.last_name.data, \
        email=signup_form.email.data.lower())
        user.set_password(signup_form.password.data)
        db.session.add(user)
        db.session.commit()
        email_status = send_verification_email(user)
        login_user(user)
        if email_status == 200:
            flash("Welcome! Please check your inbox to verify your email.")
        else:
            flash('Verification email failed to send, please contact ' + admin_email, 'error')
        next = request.args.get('next')
        if not next or url_parse(next).netloc != '':
            return redirect(url_for('start_page'))
        return redirect(next)
    return render_template('signin.html', title='Sign in', form=form, signup_form=signup_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already signed in.')
        return redirect(url_for('start_page'))
    form = LoginForm()
    signup_form = SignupForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'error')
            return redirect(url_for('signin'))
        login_user(user)
        if user.is_verified != True:
            email_status = send_verification_email(user)
            if email_status == 200:
                flash('Please check your inbox to verify your email.')
            else:
                flash('Verification email did not send. Please contact ' + admin_email)
        next = request.args.get('next')
        if not next or url_parse(next).netloc != '':
            return redirect(url_for('start_page'))
        return redirect(next)
    return render_template('signin.html', title='Sign in', form=form, signup_form=signup_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('signin'))


@app.route('/start-page')
def start_page():
    if current_user.is_admin:
        return redirect(url_for('items'))
    else:
        return redirect(url_for('index'))


@app.route('/verify-email/<token>', methods=['GET', 'POST'])
def verify_email(token):
    logout_user()
    user = User.verify_email_token(token)
    if user:
        login_user(user)
        user.is_verified = True
        db.session.add(user)
        db.session.commit()
        flash('Thank you for verifying your account.')
        return redirect(url_for('start_page'))
    else:
        flash('Your verification link is expired or invalid. Log in to receive a new link.', 'error')
        return redirect(url_for('signin'))


@app.route('/request-password-reset', methods=['GET', 'POST'])
def request_password_reset():
    form = RequestPasswordResetForm()
    if form.validate_on_submit():
        if hcaptcha.verify():
            pass
        else:
            flash('A computer has questioned your humanity. Please try again.', 'error')
            return redirect(url_for('request_password_reset'))
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            email_status = send_password_reset_email(user)
            if email_status == 200:
                flash('Check your email for instructions to reset your password.')
            else:
                flash('Email failed to send, please contact ' + admin_email, 'error')
        else:
            flash('Check your email for instructions to reset your password')
        return redirect(url_for('signin'))
    return render_template('request-password-reset.html', title='Reset password', form=form)


@app.route('/set-password/<token>', methods=['GET', 'POST'])
def set_password(token):
    user = User.verify_email_token(token)
    if not user:
        flash('The password reset link is expired or invalid. Please try again.', 'error')
        return redirect(url_for('request_password_reset'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.is_verified = True
        db.session.commit()
        login_user(user)
        flash('Your password has been saved.')
        return redirect(url_for('start_page'))
    return render_template('set-password.html', form=form)


@app.route('/users', methods=['GET', 'POST'])
@admin_required
def users():
    form = UserForm(None)
    if form.validate_on_submit():
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, \
            email=form.email.data.lower(), is_admin=False)
        try:
            db.session.add(user)
            db.session.commit()
            flash(user.first_name + ' added')
        except:
            db.session.rollback()
            flash(user.first_name + ' could not be added', 'error')
            return redirect(url_for('users'))
        return redirect(url_for('users'))
    return render_template('users.html', title="Users", form=form)


@app.route('/edit-user/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_user(id):
    user = User.query.get_or_404(id)
    form = UserForm(user.email, obj=user)
    if form.validate_on_submit():
        if 'save' in request.form:
            user.first_name=form.first_name.data
            user.last_name=form.last_name.data
            user.email=form.email.data.lower()
            user.is_admin=form.is_admin.data

            try:
                db.session.add(user)
                db.session.commit()
                flash(user.first_name + ' updated')
            except:
                db.session.rollback()
                flash(user.first_name + ' could not be updated', 'error')
                return redirect(url_for('users'))
        elif 'delete' in request.form:
            db.session.delete(user)
            db.session.commit()
            flash('Deleted ' + user.first_name)
        else:
            flash('Code error in POST request', 'error')
        return redirect(url_for('users'))
    elif request.method == "GET":
        form.first_name.data=user.first_name
        form.last_name.data=user.last_name
        form.email.data=user.email
        form.is_admin.data=user.is_admin
    return render_template('edit-user.html', title='Edit User', form=form, user=user)


@app.route('/items', methods=['GET', 'POST'])
@admin_required
def items():
    form = ItemForm()
    items = Item.query.order_by(Item.order).all()
    categories = Item.query.with_entities(Item.category).distinct()
    if form.validate_on_submit():
        item = Item(name=form.name.data.lower(), category=form.category.data.lower(), price=form.price.data, \
            description=form.description.data, is_veg=form.is_veg.data)
        try:
            db.session.add(item)
            db.session.flush()
            item.order = item.id
            db.session.add(item)
            db.session.commit()
            flash(item.name + ' added')
        except:
            db.session.rollback()
            flash(item.name + ' could not be added', 'error')
        return redirect(url_for('items'))
    return render_template('items.html', title="Menu items", form=form, items=items, categories=categories)


@app.route('/edit-item/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_item(id):
    form = ItemForm()
    item = Item.query.get_or_404(id)
    if form.validate_on_submit():
        if 'save' in request.form:
            item.name=form.name.data.lower()
            item.category=form.category.data.lower()
            item.price=form.price.data
            item.description=form.description.data
            item.order=form.order.data
            item.is_veg=form.is_veg.data

            # if form.category_id.data == 0:
            #     category = Category(name=form.category_id.data)
            # else:
            #     category = Category.query.filter_by(name=form.category_id.data).first()

            try:
                db.session.add(item)
                db.session.commit()
                flash(item.name + ' updated')
            except:
                db.session.rollback()
                flash(item.name + ' could not be updated', 'error')
        elif 'delete' in request.form:
            db.session.delete(item)
            db.session.commit()
            flash('Deleted ' + item.name)
        else:
            flash('Code error in POST request', 'error')
        return redirect(url_for('items'))
    elif request.method == "GET":
        form.name.data=item.name
        form.category.data=item.category
        form.price.data=item.price
        form.description.data=item.description
        form.order.data=item.order
        form.is_veg.data=item.is_veg
    return render_template('edit-item.html', title="Edit item", form=form, item=item)


@app.route("/download/<filename>")
def download_file (filename):
    path = os.path.join(app.root_path, 'static/files/')
    return send_from_directory(path, filename, as_attachment=False)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'img/favicons/favicon.ico')

@app.route('/manifest.webmanifest')
def webmanifest():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'img/favicons/manifest.webmanifest')

@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])

@app.route("/sitemap")
@app.route("/sitemap/")
@app.route("/sitemap.xml")
def sitemap():
    """
        Route to dynamically generate a sitemap of your website/application.
        lastmod and priority tags omitted on static pages.
        lastmod included on dynamic content such as blog posts.
    """
    #from urllib.parse import urlparse

    host_components = url_parse(request.host_url)
    host_base = host_components.scheme + "://" + host_components.netloc

    # Static routes with static content
    static_urls = list()
    for rule in app.url_map.iter_rules():
        if not str(rule).startswith("/admin") and not str(rule).startswith("/user"):
            if "GET" in rule.methods and len(rule.arguments) == 0:
                url = {
                    "loc": f"{host_base}{str(rule)}"
                }
                static_urls.append(url)

    xml_sitemap = render_template('sitemap/sitemap.xml', static_urls=static_urls, host_base=host_base) #dynamic_urls=dynamic_urls)
    response = make_response(xml_sitemap)
    response.headers["Content-Type"] = "application/xml"

    return response
