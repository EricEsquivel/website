from flask import Flask, flash, render_template, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
import hashlib
from datetime import datetime
import uuid

# Main
app = Flask(__name__)
app.config["SECRET_KEY"] = "aqw234yahawerawwikrd"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database1.db"
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "sqlalchemy"
db = SQLAlchemy(app)
app.config["SESSION_SQLALCHEMY"] = db
Session(app)


######### Session checker and update database functions ############

def ifnotloggedinexecute(func): # this is a decorator; if user is not logged in proceed, otherwise redirect to home page. Used for /login and /register
    def wrapper():
            try:
                if session["value"]:
                    return redirect("/")
                    flash("You are already logged in!", category="error")
                else:
                    func()
            except KeyError:
                print("This thing worked")
                return redirect("/logout")
    return wrapper

def ifloggedinexecute(func): # this is a decorator; if user is logged in proceed, otherwise say you don't have access and redirect to home page. Used for every other route.
    def wrapper2():
            try:
                if session["value"]:
                    func()
                else:
                    flash("You don't have access to this page!", category="error")
                    return redirect("/")
            except KeyError:
                return redirect("/logout")
    return wrapper2

# update tables after changing account info
def update_db(user, postsuser, msgsusersender, msgsuserrecipient):
    for i in postsuser:
        i.author = user.username # change usernames in Post_table to be the new username
    for i in msgsusersender:
        i.sender = user.username # change usernames in Msgs_table where user is sender to new username
    for i in msgsuserrecipient:
        i.recipient = user.username # change usernames in Msgs_table where user is recipient to new username

######################################################################


### Database Tables Below ###

class Users_table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    useruuid = db.Column(db.String, unique=True, nullable=False)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    timecreated = db.Column(db.String, nullable=False)

    def __repr__(self):
        return self


class Posts_table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, unique=False, nullable=True)
    content = db.Column(db.Text)
    author = db.Column(db.String)
    timeposted = db.Column(db.String, nullable=False)

    def __repr__(self):
        return self


class Msgs_table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    senderuuid = db.Column(db.String)
    sender = db.Column(db.String)
    recipientuuid = db.Column(db.String)
    recipient = db.Column(db.String)
    timesent = db.Column(db.String, nullable=False)

    def __repr__(self):
        return self

######


###################### Routes Below ###########################

# Go to website home page #
@app.route("/")
def home():
    return render_template("homepage.html")


# View your own user dashboard #
@ifloggedinexecute
@app.route("/dashboard")
def dashboard():
    user = Users_table.query.filter_by(useruuid=session["value"]).first()
    return render_template("dashboard.html",user=user)


# View your accounts page #
@ifloggedinexecute
@app.route("/accounts", methods = ["GET", "POST"])
def accounts():
    user = Users_table.query.filter_by(useruuid=session["value"]).first()
    postsuser = Posts_table.query.filter_by(author=user.username).all()
    msgsusersender = Msgs_table.query.filter_by(senderuuid=session["value"]).all()
    msgsuserrecipient = Msgs_table.query.filter_by(recipientuuid=session["value"]).all()
    if request.method == "GET":
        return render_template("accounts.html",user=user)
    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        hashedpassword = hashlib.sha256(password.encode()).hexdigest()
        found = Users_table.query.filter_by(username=request.form.get("username")).first()
        if found:
            flash("That username is already taken.", category="error")
        elif username == "" and password == "":
            flash("Nothing entered.", category="error")
        elif username == "":
            user.password = hashedpassword
            db.session.commit()
            flash("Account updated.", category="success")
        elif password == "":
            user.username = username
            update_db(user, postsuser, msgsusersender, msgsuserrecipient)
            db.session.commit()
            flash("Account updated.", category="success")
        else:
            user.username = username # change username in Users_table to be the new username
            update_db(user, postsuser, msgsusersender, msgsuserrecipient)
            user.password = hashedpassword # change password in Users_table to be the new password
            db.session.commit() # commit to db
            flash("Account updated.", category="success")
        return render_template("accounts.html",user=user)
    flash("You don't have access to this page!", category="error")
    return redirect("/")


# Create a post #
@ifloggedinexecute
@app.route("/createpost", methods = ["GET", "POST"])
def createpost():
    user = Users_table.query.filter_by(useruuid=session["value"]).first()
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        author = user.username
        if len(title) == 0:
            flash("title is blank", category="error")
        elif len(content) == 0:
            flash("content is blank", category="error")
        else:
            userpost = Posts_table(content=content, title=title, author=author, timeposted=datetime.now.strftime('%D %H:%M')) # Creating post
            db.session.add(userpost)
            db.session.commit()
            flash("Post created", category="success")
    return render_template("createpost.html")


# Send a message to someone #
@ifloggedinexecute
@app.route("/sendmsg", methods = ["GET", "POST"])
def sendmsg():
    senderuuid = Users_table.query.filter_by(useruuid=session["value"]).first().useruuid
    if request.method == "POST":
        content = request.form.get("content")
        recipient = request.form.get("recipient")
        if len(content) == 0:
            flash("Content is blank", category="error")
        elif len(recipient) == 0:
            flash("Recipient is blank", category="error")
        else:
            # query for first username found in database with the username entered
            recipientfound = Users_table.query.filter_by(username=recipient).first()
            # check if the 'found' query is valid (if not it would return None which is false),
            # and username's password is equal to password entered
            if recipientfound: # send message to user
                recipientuuid = recipientfound.useruuid
                createmsg = Msgs_table(content=content, senderuuid=senderuuid, sender=Users_table.query.filter_by(useruuid=senderuuid).first().username, recipientuuid=recipientuuid, recipient=Users_table.query.filter_by(useruuid=recipientuuid).first().username, timesent=datetime.now.strftime('%D %H:%M')) # Creating post
                db.session.add(createmsg)
                db.session.commit()
                flash(f"Message sent!", category="success")
            else:
                flash("Invalid user", category="error")
    return render_template("sendmsg.html")


# View public posts #
@ifloggedinexecute
@app.route("/posts")
def posts():
    posts = Posts_table.query.all()
    return render_template("posts.html",posts=posts)


# View your own user messages #
@ifloggedinexecute
@app.route("/messages")
def messages():
    myuseruuid = Users_table.query.filter_by(useruuid=session["value"]).first().useruuid # what is my uuid
    messages = Msgs_table.query.filter_by(recipientuuid=myuseruuid).all() # messages from msgs table with my uuid
    return render_template("messages.html", messages=messages)


# Default page is the login, and it will run a check against the database to make sure account exists #
@ifnotloggedinexecute
@app.route("/login", methods = ["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if len(username) == 0:
            flash("You need to type in a username!", category="error")
        elif len(password) == 0:
            flash("You need to type in a password!", category="error")
        else:
            # hash entered password
            hashedpassword = hashlib.sha256(password.encode()).hexdigest()
            # query for first username found in database with the username entered
            found = Users_table.query.filter_by(username=username).first()
            # check if the 'found' query is valid (if not it would return None which is false),
            # and username's password is equal to password entered
            if found and hashedpassword == found.password: #hashed password check here
                session["value"] = found.useruuid
                flash(f"Signed in as {username}!", category="success")
                return redirect("/")
            else:
                flash("Invalid credentials!", category="error")
    return render_template("login.html")


# Route for registration page, run a check against database to make sure account doesn't exist already #
@ifnotloggedinexecute
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if len(username) == 0:
            flash("You need to type in a username!", category="error")
        elif len(password) == 0:
            flash("You need to type in a password!", category="error")
        elif username == "None" or username == "none":
            flash("You need to type in a username!", category="error")
        else:
            found = Users_table.query.filter_by(username=username).first()
            # Run final checks to see if username is taken
            if found:
                flash("That username already exists!", category="error")
            else:
                # hash entered password
                hashedpassword = hashlib.sha256(password.encode()).hexdigest()
                useruuid = str(uuid.uuid4())
                # create register account and add to database
                newaccount = Users_table(username=username, password=hashedpassword, useruuid=useruuid, timecreated=datetime.now().strftime('%D %H:%M')) # setting hashpassword in account register here
                db.session.add(newaccount)
                db.session.commit()
                flash("Account registered!", category="success")
    return render_template("register.html")


# Route for the logout page, and log user out #
@app.route("/logout")
def logout():
    session["value"] = None            
    return redirect("/")


# Route for users page, just shows the database table for testing #
                    # REMOVE IN PRODUCTION #
@app.route("/users")
def seeusers():
    if session["value"] == Users_table.query.filter_by(username="admin").first().useruuid:
        allusers = Users_table.query.all()
        return render_template("users.html",allusers=allusers)
    else:
        flash("You don't have access to this page!", category="error")
        return redirect("/")

#######


# ERROR PAGES #
@app.errorhandler(404)
def pagenotfound(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def servererror(error):
    return render_template("servererror.html"), 500


# Run in debug mode so that when you make changes, it auto updates the server without having to restart #
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(host="10.0.2.15", port=5000, debug=True)