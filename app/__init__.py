from flask import Flask
from flask import request
import vra.vra as vra
app = Flask(__name__)

@app.route("/proxy", methods=['POST'])
def run_vra():
    fr = vra.do_flask_post(request.headers.get('token'), request.get_json())
    return fr.message, fr.code
    
