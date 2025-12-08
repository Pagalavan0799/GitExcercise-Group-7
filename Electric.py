from flask import Flask, render_template, request

app = Flask(__name__)

RATE_PER_KWH = 0.50

