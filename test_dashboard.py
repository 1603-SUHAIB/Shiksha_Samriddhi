from flask import Flask, request, jsonify, render_template
from pymongo import MongoClient

app = Flask(__name__)

# MongoDB connection setup
try:
    client = MongoClient('mongodb://localhost:27017/')
    db = client['institution_portal']
    users = db['users']
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")


@app.route('/')
def dashboard():
    try:
        school = users.find_one({'udiseCode': "11234567890"})

        if not school:
            return "School not found", 404

        return render_template('ai_tool.html', school=school)
    except Exception as e:
        print(f"Error in dashboard route: {e}")
        return "Internal Server Error", 500


if __name__ == '__main__':
    app.run(debug=True)
