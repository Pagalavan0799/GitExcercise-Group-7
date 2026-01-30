from flask import Flask, render_template, request

app = Flask(__name__)

E_RATE = 0.33  
W_RATE = 0.66 

@app.route('/', methods=['GET', 'POST'])
def calculate_all():
    e_usage = 0.0
    w_usage = 0.0
    total_price = 0.0
    
    if request.method == 'POST':
        try:
            e_usage = float(request.form.get('e_usage', 0) or 0)
            w_usage = float(request.form.get('w_usage', 0) or 0)

            total_price = (e_usage * E_RATE) + (w_usage * W_RATE)
        except ValueError:
            pass

    return render_template('Total2.html', 
                           e_usage=e_usage, 
                           w_usage=w_usage, 
                           total_price=total_price)

if __name__ == '__main__':
    app.run(port=5002, debug=True)