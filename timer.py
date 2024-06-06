from flask import Blueprint, Flask, jsonify
import datetime

#timer = Blueprint('Blueprint', __name__)


def get_current_time():
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({"current_time": current_time})
