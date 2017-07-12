from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
import random
import string

# Imports for database
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

# Imports for OAuth login
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

# Connect to Database and create database session
engine = create_engine('sqlite:///catalogwithusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# JSON APIs to view Catalog Information
@app.route('/catalog/JSON')
def catalogJSON():
    catalog = session.query(Category).all()
    return jsonify(Categories=[category.serialize for category in catalog])


# JSON APIs to view Catalog Information
@app.route('/catalog/<string:category_name>/JSON')
def catalogItemsJSON(category_name):
    selected_category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category=selected_category).all()
    return jsonify(Items=[item.serialize for item in items])


# JSON APIs to view Catalog Information
@app.route('/catalog/<string:category_name>/<string:item_name>/JSON')
def catalogItemJSON(category_name, item_name):
    selected_category = session.query(Category).filter_by(name=category_name).one()
    selected_item = session.query(Item).filter_by(category=selected_category, name=item_name).one()
    return jsonify(selected_item.serialize)


# Show all categories
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template('public_catalog.html', categories=categories)
    else:
        return render_template('catalog.html', categories=categories)


# Show category items
@app.route('/catalog/<string:category_name>/')
def showCategoryItems(category_name):
    selected_category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category=selected_category).all()
    if 'username' not in login_session:
        return render_template('public_category_items.html', items=items)
    else:
        return render_template('category_items.html', items=items)


# Show item details
@app.route('/catalog/<string:category_name>/<string:item_name>/')
def showItem(category_name, item_name):
    item_category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(name=item_name, category=item_category).one()

    if 'username' not in login_session:
        return render_template('public_item.html', item=item)
    else:
        return render_template('item.html', item=item)


# New item
@app.route('/catalog/new/', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    categories = session.query(Category).all()

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = session.query(Category).filter_by(name=request.form['category']).one()
        image_url = request.form['image_url']

        if name and description:
            newItem = Item(
                name=name,
                description=description,
                image_url=image_url,
                category=category,
                user_id=login_session['user_id']
            )
            session.add(newItem)
            session.commit()

            return redirect(url_for('showCatalog'))
        else:
            return render_template('new_item.html', categories=categories, error="Name and description please!")
    else:
        return render_template('new_item.html', categories=categories)


# Edit item
@app.route('/catalog/<string:category_name>/<string:item_name>/edit/', methods=['GET', 'POST'])
def editItem(category_name, item_name):
    if 'username' not in login_session:
        flash("Please login before editing items.")
        return redirect(url_for('showLogin'))
    categories = session.query(Category).all()
    item_category = session.query(Category).filter_by(name=category_name).one()
    itemToEdit = session.query(Item).filter_by(name=item_name, category=item_category).one()

    if login_session['user_id'] != itemToEdit.user_id:
        flash("You can't edit that item.")
        return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = session.query(Category).filter_by(name=request.form['category']).one()

        if name and description:
            itemToEdit.name = name
            itemToEdit.description = description
            itemToEdit.category = category
            session.add(itemToEdit)
            session.commit()
            flash("Item edited successfully!")
            return redirect(url_for('showCatalog'))
        else:
            return render_template(
                'edit_Item.html',
                categories=categories,
                item=itemToEdit,
                category_name=item_category.name,
                error="Name and description please!"
            )
    else:
        return render_template(
            'edit_item.html',
            categories=categories,
            item=itemToEdit,
            category_name=item_category.name
        )


# Delete item
@app.route('/catalog/<string:category_name>/<string:item_name>/delete/', methods=['GET', 'POST'])
def deleteItem(category_name, item_name):
    if 'username' not in login_session:
        flash("Please login before deleteing items.")
        return redirect(url_for('showLogin'))
    item_category = session.query(Category).filter_by(name=category_name).one()
    itemToDelete = session.query(Item).filter_by(name=item_name, category=item_category).one()

    if login_session['user_id'] != itemToDelete.user_id:
        flash("You can't delete that item.")
        return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Item deleted successfully!")
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'delete_item.html',
            item=itemToDelete,
            category_name=item_category.name
        )


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('g_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    client_id = json.loads(open('g_client_secrets.json', 'r').read())['web']['client_id']
    if result['issued_to'] != client_id:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id


    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("Now logged in as %s" % login_session['username'])
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']

    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] != '200':
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    #exchange client token for long-lived server-side token with GET
    app_id = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/v2.9/oauth/access_token?'
           'grant_type=fb_exchange_token&client_id=%s&client_secret=%s'
           '&fb_exchange_token=%s') % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    token = 'access_token=' + data['access_token']
    # see: https://discussions.udacity.com/t/
    #   issues-with-facebook-oauth-access-token/233840?source_topic_id=174342

    # Use token to get user info from API
    # make API call with new token
    url = 'https://graph.facebook.com/v2.9/me?%s&fields=name,id,email,picture' % token

    #new: put the "picture" here, it is now part of the default "public_profile"

    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']
    login_session['picture'] = data['picture']["data"]["url"]
    login_session['access_token'] = access_token

    #see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1><img src="'
    output += login_session['picture']
    output += ' ">'

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)