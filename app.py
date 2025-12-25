from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from detector import analyze_url
import os

# Initialize Flask and point to your templates folder
app = Flask(__name__, template_folder='templates')
CORS(app)

# Route for the Scanner (Home Page)
@app.route('/')
def home():
    return render_template('index.html')

# Route for the Academy Page (Fixes the "Not Found" error)
@app.route('/education.html')
def academy():
    return render_template('education.html')

# The "Brain" - Analysis Route
@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.json
        url = data.get('url', '')
        if not url:
            return jsonify({"error": "No input provided"}), 400
        
        # Execute analysis using your detector script
        result = analyze_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    # host='0.0.0.0' allows your phone to talk to your laptop
    app.run(host='0.0.0.0', port=5000, debug=True)