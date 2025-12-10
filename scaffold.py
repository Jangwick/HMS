import os

subsystems = [
    # HR
    {"code": "hr2", "dept": "hr", "name": "Talent Development", "color": "#06B6D4", "icon": "bi-mortarboard", "db_bind": "hr2"},
    {"code": "hr3", "dept": "hr", "name": "Workforce Operations", "color": "#0EA5E9", "icon": "bi-clock-history", "db_bind": "hr3"},
    {"code": "hr4", "dept": "hr", "name": "Compensation & Analytics", "color": "#6366F1", "icon": "bi-graph-up-arrow", "db_bind": "hr4"},
    
    # Core Transaction
    {"code": "ct1", "dept": "core_transaction", "name": "Patient Access", "color": "#10B981", "icon": "bi-person-badge", "db_bind": "ct1"},
    {"code": "ct2", "dept": "core_transaction", "name": "Clinical Operations", "color": "#14B8A6", "icon": "bi-clipboard-pulse", "db_bind": "ct2"},
    {"code": "ct3", "dept": "core_transaction", "name": "Admin & Finance", "color": "#059669", "icon": "bi-building-gear", "db_bind": "ct3"},
    
    # Logistics
    {"code": "log1", "dept": "logistics", "name": "Smart Supply Chain", "color": "#F59E0B", "icon": "bi-box-seam", "db_bind": "log1"},
    {"code": "log2", "dept": "logistics", "name": "Fleet Operations", "color": "#F97316", "icon": "bi-truck", "db_bind": "log2"},
    
    # Financials
    {"code": "fin1", "dept": "financials", "name": "Budget Management", "color": "#8B5CF6", "icon": "bi-pie-chart", "db_bind": "fin1"},
    {"code": "fin2", "dept": "financials", "name": "Collection Management", "color": "#A855F7", "icon": "bi-wallet2", "db_bind": "fin2"},
    {"code": "fin3", "dept": "financials", "name": "Disbursement Management", "color": "#9333EA", "icon": "bi-cash-stack", "db_bind": "fin3"},
    {"code": "fin4", "dept": "financials", "name": "General Ledger", "color": "#7C3AED", "icon": "bi-journal-text", "db_bind": "fin4"},
    {"code": "fin5", "dept": "financials", "name": "Financial Intelligence", "color": "#6D28D9", "icon": "bi-graph-up", "db_bind": "fin5"},
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def create_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)

def generate_models():
    # Group by department to create/append to model files
    dept_models = {}
    for sub in subsystems:
        dept = sub['dept']
        if dept == 'core_transaction': dept = 'ct' # Shorten for filename if desired, or keep full. Let's use 'ct_users.py' etc
        if dept == 'logistics': dept = 'log'
        if dept == 'financials': dept = 'fin'
        
        if dept not in dept_models:
            dept_models[dept] = []
        dept_models[dept].append(sub)

    for dept, subs in dept_models.items():
        filename = f"models/{dept}_users.py"
        if dept == 'hr': filename = "models/hr_user.py" # Append to existing
        
        content = ""
        if not os.path.exists(filename):
            content = "from app import db\nfrom models.base_user import BaseUser\n\n"
        
        for sub in subs:
            class_name = sub['code'].upper() + "User"
            content += f"""class {class_name}(BaseUser):
    __tablename__ = '{sub['code']}_users'
    __bind_key__ = '{sub['db_bind']}'
    
    department = db.Column(db.String(50), default='{sub['dept'].upper()}')
    role = db.Column(db.String(50), default='Staff')

"""
        
        with open(filename, "a") as f:
            f.write(content)
        print(f"Updated {filename}")

def generate_routes():
    for sub in subsystems:
        dept_path = f"routes/{sub['dept']}"
        create_directory(dept_path)
        
        filename = f"{dept_path}/{sub['code']}.py"
        class_name = sub['code'].upper() + "User"
        model_import_file = "hr_user" if sub['dept'] == 'hr' else f"{sub['dept'].replace('core_transaction', 'ct').replace('logistics', 'log').replace('financials', 'fin')}_users"
        
        content = f"""from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required
from app import db
from models.{model_import_file} import {class_name}
from datetime import datetime
import pytz

{sub['code']}_bp = Blueprint('{sub['code']}', __name__, template_folder='templates')

@ {sub['code']}_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = {class_name}.query.filter_by(username=username).first()
        
        if user:
            # Check for lockout
            if user.is_locked():
                 remaining_seconds = int((user.account_locked_until - datetime.utcnow()).total_seconds())
                 
                 # Convert to Manila time for display
                 tz_manila = pytz.timezone('Asia/Manila')
                 # Ensure account_locked_until is treated as UTC (since we store it as naive UTC)
                 locked_until_utc = pytz.utc.localize(user.account_locked_until)
                 unlock_time_manila = locked_until_utc.astimezone(tz_manila)
                 unlock_time_str = unlock_time_manila.strftime("%I:%M%p").lower()
                 
                 flash(f'Account locked. Try again at {{unlock_time_str}}', 'danger')
                 return render_template('subsystems/{sub['dept']}/{sub['code']}/login.html', remaining_seconds=remaining_seconds)

            if user.check_password(password):
                # Check for password expiration
                if user.password_expires_at and user.password_expires_at < datetime.utcnow():
                    flash('Your password has expired. Please contact IT to reset it.', 'warning')
                    return render_template('subsystems/{sub['dept']}/{sub['code']}/login.html')

                user.register_successful_login()
                db.session.commit()
                login_user(user)
                
                # Check if password is about to expire (e.g., within 10 days)
                days_left = (user.password_expires_at - datetime.utcnow()).days
                if days_left <= 10:
                    flash(f'Warning: Your password will expire in {{days_left}} days.', 'warning')
                    
                return redirect(url_for('{sub['code']}.dashboard'))
            else:
                user.register_failed_login()
                db.session.commit()
                
                if user.is_locked():
                     remaining_seconds = int((user.account_locked_until - datetime.utcnow()).total_seconds())
                     
                     # Convert to Manila time for display
                     tz_manila = pytz.timezone('Asia/Manila')
                     locked_until_utc = pytz.utc.localize(user.account_locked_until)
                     unlock_time_manila = locked_until_utc.astimezone(tz_manila)
                     unlock_time_str = unlock_time_manila.strftime("%I:%M%p").lower()
                     
                     flash(f'Account locked. Try again at {{unlock_time_str}}', 'danger')
                     return render_template('subsystems/{sub['dept']}/{sub['code']}/login.html', remaining_seconds=remaining_seconds)
                else:
                    remaining = 5 - user.failed_login_attempts
                    if remaining > 0:
                        flash(f'Invalid credentials. {{remaining}} attempts remaining before lockout.', 'danger')
                    else:
                        flash('Account locked due to too many failed attempts.', 'danger')
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('subsystems/{sub['dept']}/{sub['code']}/login.html')
@ {sub['code']}_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('subsystems/{sub['dept']}/{sub['code']}/dashboard.html', now=datetime.utcnow)

@ {sub['code']}_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('{sub['code']}.login'))
"""
        # Fix the decorator space
        content = content.replace("@ ", "@")
        
        with open(filename, "w") as f:
            f.write(content)
        print(f"Created {filename}")

def generate_templates():
    for sub in subsystems:
        template_path = f"templates/subsystems/{sub['dept']}/{sub['code']}"
        create_directory(template_path)
        
        # Login Template
        login_html = f"""{{% extends "base/base.html" %}}

{{% block title %}}Login - {sub['code'].upper()} {sub['name']}{{% endblock %}}

{{% block content %}}
<div class="min-h-screen flex items-center justify-center bg-gray-50 relative overflow-hidden">
    <!-- Background Decoration -->
    <div class="absolute top-0 left-0 w-full h-full overflow-hidden z-0 pointer-events-none">
        <div class="absolute -top-[20%] -left-[10%] w-[70%] h-[70%] rounded-full bg-gradient-to-r from-[{sub['color']}] to-transparent opacity-5 blur-3xl"></div>
        <div class="absolute -bottom-[20%] -right-[10%] w-[70%] h-[70%] rounded-full bg-gradient-to-l from-[{sub['color']}] to-transparent opacity-5 blur-3xl"></div>
    </div>

    <div class="max-w-md w-full bg-white/90 backdrop-blur-sm p-8 sm:p-10 rounded-3xl shadow-2xl border border-gray-100 relative z-10 mx-4">
        <!-- Header Icon -->
        <div class="absolute -top-10 left-1/2 transform -translate-x-1/2">
            <div class="w-20 h-20 bg-gradient-to-br from-[{sub['color']}] to-gray-800 rounded-2xl flex items-center justify-center shadow-lg border-4 border-white text-white">
                <i class="bi {sub['icon']} text-4xl"></i>
            </div>
        </div>
        
        <div class="mt-12 text-center space-y-2">
            <h2 class="text-3xl font-bold text-gray-900 tracking-tight">
                {sub['code'].upper()}
            </h2>
            <p class="text-sm font-bold text-[{sub['color']}] uppercase tracking-wider">{sub['name']}</p>
            <p class="text-gray-500 text-sm">Secure Access Portal</p>
        </div>
        
        <div class="mt-8">
            {{% with messages = get_flashed_messages(with_categories=true) %}}
              {{% if messages %}}
                {{% for category, message in messages %}}
                  <div class="rounded-xl bg-{{{{ 'red' if category == 'danger' else 'green' }}}}-50 p-4 mb-4 border border-{{{{ 'red' if category == 'danger' else 'green' }}}}-100 flex items-start animate-fade-in-down">
                    <div class="flex-shrink-0">
                      <i class="bi bi-{{{{ 'x-circle-fill' if category == 'danger' else 'check-circle-fill' }}}} text-{{{{ 'red' if category == 'danger' else 'green' }}}}-500 text-lg"></i>
                    </div>
                    <div class="ml-3">
                      <p class="text-sm font-medium text-{{{{ 'red' if category == 'danger' else 'green' }}}}-800">
                        {{{{ message }}}}
                      </p>
                    </div>
                  </div>
                {{% endfor %}}
              {{% endif %}}
            {{% endwith %}}
            
            {{% if remaining_seconds %}}
            <div id="lockout-timer" class="rounded-xl bg-red-50 p-4 mb-6 text-center border border-red-100 animate-pulse">
                <p class="text-sm font-medium text-red-800">
                     Time remaining: <span id="countdown" class="font-bold text-lg font-mono"></span>
                </p>
            </div>
            <script>
                document.addEventListener('DOMContentLoaded', function() {{
                    var remaining = {{{{ remaining_seconds }}}};
                    
                    function updateTimer() {{
                        if (remaining < 0) {{
                            document.getElementById("lockout-timer").innerHTML = '<p class="text-sm font-medium text-green-800">Lockout expired. Please refresh to login.</p>';
                            setTimeout(function() {{ location.reload(); }}, 2000);
                            return;
                        }}
                        
                        var minutes = Math.floor(remaining / 60);
                        var seconds = Math.floor(remaining % 60);
                        
                        document.getElementById("countdown").innerHTML = minutes + "m " + seconds + "s ";
                        remaining--;
                    }}
                    
                    updateTimer(); // Run immediately
                    setInterval(updateTimer, 1000);
                }});
            </script>
            {{% endif %}}

            <form class="space-y-6" action="{{{{ url_for('{sub['code']}.login') }}}}" method="POST">
                <input type="hidden" name="csrf_token" value="{{{{ csrf_token() }}}}"/>
                <div class="space-y-4">
                    <div>
                        <label for="username" class="block text-sm font-medium text-gray-700 mb-1 ml-1">Username</label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="bi bi-person text-gray-400"></i>
                            </div>
                            <input id="username" name="username" type="text" required 
                                class="block w-full pl-10 pr-3 py-3 border border-gray-200 rounded-xl text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-[{sub['color']}] focus:border-transparent transition-all duration-200 bg-gray-50 focus:bg-white sm:text-sm" 
                                placeholder="Enter your username">
                        </div>
                    </div>
                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-700 mb-1 ml-1">Password</label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="bi bi-lock text-gray-400"></i>
                            </div>
                            <input id="password" name="password" type="password" required 
                                class="block w-full pl-10 pr-3 py-3 border border-gray-200 rounded-xl text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-[{sub['color']}] focus:border-transparent transition-all duration-200 bg-gray-50 focus:bg-white sm:text-sm" 
                                placeholder="Enter your password">
                        </div>
                    </div>
                </div>

                <div>
                    <button type="submit" 
                        class="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-bold rounded-xl text-white bg-gradient-to-r from-[{sub['color']}] to-gray-800 hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-[{sub['color']}] transition-all duration-200 shadow-lg shadow-[{sub['color']}]/30 transform hover:-translate-y-0.5">
                        <span class="absolute left-0 inset-y-0 flex items-center pl-3">
                            <i class="bi bi-box-arrow-in-right group-hover:text-white/80 transition-colors"></i>
                        </span>
                        Sign in
                    </button>
                </div>
                
                <div class="text-center pt-2">
                    <a href="{{{{ url_for('portal.index') }}}}" class="inline-flex items-center text-sm text-gray-500 hover:text-gray-900 transition-colors group">
                        <i class="bi bi-arrow-left mr-2 group-hover:-translate-x-1 transition-transform"></i> Back to Portal
                    </a>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Footer -->
    <div class="absolute bottom-6 text-center w-full text-xs text-gray-400">
        &copy; 2025 Hospital Management System. Secure Environment.
    </div>
</div>
{{% endblock %}}
"""
        with open(f"{template_path}/login.html", "w") as f:
            f.write(login_html)

        # Dashboard Template
        dashboard_html = f"""{{% extends "base/base.html" %}}

{{% block title %}}Dashboard - {sub['code'].upper()}{{% endblock %}}

{{% block content %}}
<div class="flex h-screen bg-gray-50 overflow-hidden font-sans">
    <!-- Sidebar -->
    <aside class="w-72 bg-white shadow-2xl hidden md:flex flex-col z-20 border-r border-gray-100">
        <div class="h-20 flex items-center px-8 border-b border-gray-100">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-[{sub['color']}] to-gray-800 flex items-center justify-center shadow-lg mr-4 text-white">
                <i class="bi {sub['icon']} text-lg"></i>
            </div>
            <div>
                <h1 class="text-xl font-extrabold text-gray-900 tracking-tight">{sub['code'].upper()}</h1>
                <p class="text-xs font-medium text-gray-400 uppercase tracking-wider">System</p>
            </div>
        </div>
        
        <nav class="flex-1 overflow-y-auto py-6 px-4 space-y-2">
            <p class="px-4 text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Main Menu</p>
            
            <a href="#" class="flex items-center px-4 py-3 bg-[{sub['color']}]/10 text-[{sub['color']}] rounded-xl transition-all duration-200 font-bold group shadow-sm">
                <i class="bi bi-speedometer2 text-xl mr-3 group-hover:scale-110 transition-transform"></i>
                Dashboard
            </a>
            
            <a href="#" class="flex items-center px-4 py-3 text-gray-600 hover:bg-gray-50 hover:text-gray-900 rounded-xl transition-all duration-200 font-medium group">
                <i class="bi bi-people text-xl mr-3 text-gray-400 group-hover:text-[{sub['color']}] transition-colors"></i>
                Personnel
            </a>
            
            <a href="#" class="flex items-center px-4 py-3 text-gray-600 hover:bg-gray-50 hover:text-gray-900 rounded-xl transition-all duration-200 font-medium group">
                <i class="bi bi-file-earmark-text text-xl mr-3 text-gray-400 group-hover:text-[{sub['color']}] transition-colors"></i>
                Reports
            </a>

            <p class="px-4 text-xs font-semibold text-gray-400 uppercase tracking-wider mt-6 mb-2">System</p>

            <a href="#" class="flex items-center px-4 py-3 text-gray-600 hover:bg-gray-50 hover:text-gray-900 rounded-xl transition-all duration-200 font-medium group">
                <i class="bi bi-gear text-xl mr-3 text-gray-400 group-hover:text-[{sub['color']}] transition-colors"></i>
                Settings
            </a>
        </nav>
        
        <div class="p-4 border-t border-gray-100 bg-gray-50/50">
            <div class="flex items-center mb-4 p-3 bg-white rounded-xl border border-gray-100 shadow-sm">
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-gray-700 to-gray-900 flex items-center justify-center text-white font-bold shadow-md">
                    {{{{ current_user.username[0] | upper }}}}
                </div>
                <div class="ml-3 overflow-hidden">
                    <p class="text-sm font-bold text-gray-900 truncate">{{{{ current_user.username }}}}</p>
                    <p class="text-xs text-gray-500 truncate">Administrator</p>
                </div>
            </div>
            <a href="{{{{ url_for('{sub['code']}.logout') }}}}" class="flex items-center justify-center w-full px-4 py-2.5 text-sm font-bold text-red-600 bg-red-50 rounded-xl hover:bg-red-100 transition-all duration-200 hover:shadow-md">
                <i class="bi bi-box-arrow-right mr-2"></i> Sign Out
            </a>
        </div>
    </aside>

    <!-- Main Content -->
    <div class="flex-1 flex flex-col overflow-hidden relative">
        <!-- Top Header -->
        <header class="bg-white/80 backdrop-blur-md shadow-sm h-20 flex items-center justify-between px-8 sticky top-0 z-10 border-b border-gray-100">
            <div class="flex items-center">
                <h2 class="text-2xl font-bold text-gray-800 tracking-tight">{sub['name']}</h2>
            </div>
            <div class="flex items-center space-x-4">
                <button class="p-2 text-gray-400 hover:text-[{sub['color']}] transition-colors relative">
                    <i class="bi bi-bell text-xl"></i>
                    <span class="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full border-2 border-white"></span>
                </button>
                <div class="h-8 w-px bg-gray-200 mx-2"></div>
                <span class="text-sm font-medium text-gray-500">{{{{ now().strftime('%B %d, %Y') }}}}</span>
            </div>
        </header>

        <!-- Content Scroll Area -->
        <main class="flex-1 overflow-x-hidden overflow-y-auto bg-gray-50 p-8">
            <!-- Welcome Card -->
            <div class="bg-gradient-to-r from-[{sub['color']}] to-gray-800 rounded-3xl shadow-xl p-8 text-white mb-8 relative overflow-hidden">
                <div class="absolute top-0 right-0 w-64 h-64 bg-white opacity-10 rounded-full transform translate-x-1/2 -translate-y-1/2 blur-3xl"></div>
                <div class="absolute bottom-0 left-0 w-48 h-48 bg-black opacity-10 rounded-full transform -translate-x-1/2 translate-y-1/2 blur-2xl"></div>
                
                <div class="relative z-10">
                    <h3 class="text-3xl font-bold mb-2">Welcome back, {{{{ current_user.username }}}}!</h3>
                    <p class="text-white/80 text-lg max-w-2xl">Your secure dashboard is ready. You have full access to all {sub['name']} modules and features.</p>
                    
                    <div class="mt-8 flex space-x-4">
                        <button class="px-6 py-2.5 bg-white text-[{sub['color']}] font-bold rounded-xl shadow-lg hover:bg-gray-50 transition-colors">
                            View Reports
                        </button>
                        <button class="px-6 py-2.5 bg-black/20 text-white font-bold rounded-xl hover:bg-black/30 transition-colors backdrop-blur-sm">
                            Manage Users
                        </button>
                    </div>
                </div>
            </div>

            <!-- Stats Grid Placeholder -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
                    <div class="flex items-center justify-between mb-4">
                        <h4 class="text-gray-500 text-sm font-bold uppercase">Total Active Users</h4>
                        <div class="w-10 h-10 rounded-full bg-blue-50 flex items-center justify-center text-blue-600">
                            <i class="bi bi-people-fill"></i>
                        </div>
                    </div>
                    <p class="text-3xl font-bold text-gray-900">1,248</p>
                    <p class="text-green-500 text-sm font-medium mt-2 flex items-center">
                        <i class="bi bi-arrow-up-short text-lg"></i> 12% increase
                    </p>
                </div>
                
                <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
                    <div class="flex items-center justify-between mb-4">
                        <h4 class="text-gray-500 text-sm font-bold uppercase">Pending Tasks</h4>
                        <div class="w-10 h-10 rounded-full bg-amber-50 flex items-center justify-center text-amber-600">
                            <i class="bi bi-list-task"></i>
                        </div>
                    </div>
                    <p class="text-3xl font-bold text-gray-900">34</p>
                    <p class="text-gray-400 text-sm font-medium mt-2">Requires attention</p>
                </div>
                
                <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
                    <div class="flex items-center justify-between mb-4">
                        <h4 class="text-gray-500 text-sm font-bold uppercase">System Status</h4>
                        <div class="w-10 h-10 rounded-full bg-green-50 flex items-center justify-center text-green-600">
                            <i class="bi bi-activity"></i>
                        </div>
                    </div>
                    <p class="text-3xl font-bold text-gray-900">99.9%</p>
                    <p class="text-green-500 text-sm font-medium mt-2">Operational</p>
                </div>
            </div>
            
            <!-- Empty State / Content Area -->
            <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-8 min-h-[400px] flex flex-col items-center justify-center text-center">
                <div class="w-24 h-24 bg-gray-50 rounded-full flex items-center justify-center mb-6">
                    <i class="bi {sub['icon']} text-4xl text-gray-300"></i>
                </div>
                <h4 class="text-xl font-bold text-gray-900 mb-2">Ready for Implementation</h4>
                <p class="text-gray-500 max-w-md">This module is fully authenticated. You can now start building the specific features for {sub['name']}.</p>
            </div>
        </main>
    </div>
</div>
{{% endblock %}}
"""
        with open(f"{template_path}/dashboard.html", "w") as f:
            f.write(dashboard_html)
        print(f"Created templates for {sub['code']}")

def generate_app_registration():
    print("\n--- Add this to app.py ---")
    for sub in subsystems:
        print(f"    from routes.{sub['dept']}.{sub['code']} import {sub['code']}_bp")
        print(f"    app.register_blueprint({sub['code']}_bp, url_prefix='/{sub['dept'].replace('_', '-')}/{sub['code']}')")

def generate_init_db():
    print("\n--- Add this to init_db.py ---")
    for sub in subsystems:
        class_name = sub['code'].upper() + "User"
        model_import_file = "hr_user" if sub['dept'] == 'hr' else f"{sub['dept'].replace('core_transaction', 'ct').replace('logistics', 'log').replace('financials', 'fin')}_users"
        print(f"from models.{model_import_file} import {class_name}")
        
    print("\n# Inside init_db function:")
    for sub in subsystems:
        class_name = sub['code'].upper() + "User"
        print(f"""
        if not {class_name}.query.filter_by(username='admin_{sub['code']}').first():
            user = {class_name}(
                username='admin_{sub['code']}',
                email='admin@{sub['code']}.hms.com',
                department='{sub['dept'].upper()}',
                role='Administrator'
            )
            user.set_password('Admin@12345')
            db.session.add(user)
            print("Created {sub['code']} user")
""")

if __name__ == "__main__":
    # generate_models()
    generate_routes()
    generate_templates()
    generate_app_registration()
    generate_init_db()
