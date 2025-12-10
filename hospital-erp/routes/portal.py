from flask import Blueprint, render_template

portal_bp = Blueprint('portal', __name__)

@portal_bp.route('/')
def index():
    return render_template('portal/index.html')

@portal_bp.route('/hr')
def hr_hub():
    return render_template('departments/hr_hub.html')

@portal_bp.route('/core-transaction')
def ct_hub():
    return render_template('departments/ct_hub.html')

@portal_bp.route('/logistics')
def logistics_hub():
    return render_template('departments/logistics_hub.html')

@portal_bp.route('/financials')
def financials_hub():
    return render_template('departments/financials_hub.html')
