from flask import Flask, render_template, request

app = Flask(__name__)

RATE_PER_KWH = 0.50

@app.route('/', methods=['GET', 'POST'])
def calculate_bill():
    
    kwh_consumed = None
    monthly_cost = None
    error = None

    if request.method == 'POST':
        try:
            kwh_input = request.form.get('kwh_input')
            
            kwh_consumed = float(kwh_input)
            
            if kwh_consumed < 0:
                error = "Consumption (kWh) cannot be negative."
                kwh_consumed = None 
            else:
                monthly_cost = kwh_consumed * RATE_PER_KWH
                
        except ValueError:
            error = "Invalid input. Please enter a valid number for kWh consumption."
        except Exception as e:
            error = f"An unexpected error occurred: {e}"

    return render_template(
        'index.html', 
        kwh_consumed=kwh_consumed, 
        monthly_cost=monthly_cost, 
        rate=RATE_PER_KWH, 
        error=error
    )

if __name__ == '__main__':
    app.run(debug=True)