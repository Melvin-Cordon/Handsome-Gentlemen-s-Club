#export API_KEY=pk_9028d056c2d2407e937114bfef168c57
import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash


from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    rows = db.execute("SELECT * FROM portfolio WHERE id = (:id)", id=session["user_id"] )

    if rows:
        rows[0]["cost"] = usd(float(rows[0]["cost"]))
        rows[0]["value"] = usd(float(rows[0]["value"]))

    return render_template("index.html", rows=rows)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        ticker = request.form.get("symbol")
        shares = request.form.get("shares")

        if ticker == None:
            return apology("Invalid Symbol")
        if shares == None:
            return apology("Share cant not be 0")

        price = lookup(ticker)['price']

        cost = float(price)*float(shares)

        rows = db.execute("SELECT * FROM users WHERE id = :id", id=session["user_id"])
        money = rows[0]['cash']

        if cost > money:
            return apology("You dont have enough money for this transaction")

        cash = money - cost
        db.execute("UPDATE users SET cash = (:cash) WHERE id = (:id)", cash = cash, id = session["user_id"])
        db.execute("INSERT INTO transactions (id, ticker, price, shares) VALUES (:id, :ticker, :price, :shares)", id = session["user_id"], ticker = ticker, price = price, shares = shares)


        entry_exist = (next(iter(db.execute("SELECT EXISTS(SELECT 1 FROM portfolio WHERE id=(:id) AND ticker=(:ticker))", id=session["user_id"], ticker = ticker)[0].values())))

        if entry_exist == 0:
            db.execute("INSERT INTO portfolio (id, ticker, shares, cost, value) VALUES (:id, :ticker, :shares, :cost, :value)", id = session["user_id"], ticker = ticker, shares = shares, cost = (cost), value = (cost))
            return render_template("index.html")

        #return render_template("buy.html")
    return render_template("index.html")


    return apology("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        ticker = request.form.get("symbol")
        if ticker == None:
            return apology("Invalid Symbol")
        price = lookup(ticker)
        return render_template("quoted.html", price = price['price'])
    return apology("Something went way wrong")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if username == None:
            return apology("Username can not be left blank")
        if password == None:
            return apology("Password can not be left blank")
        if password != confirmation:
            return apology("passwords do not match")

        db.execute("INSERT INTO users (username, hash) VALUES (:username, :password_hash)", username = username, password_hash = generate_password_hash(password))
        return redirect("/")




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
