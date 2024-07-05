#!/usr/bin/env python3

from flask import request, session,jsonify,make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError


from config import app, db, api
from models import User, Recipe


@app.before_request
def check_if_logged_in():
    open_access_list = [
        'signup',
        'login',
        'check_session'
    ]

    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401


class Signup(Resource):
    def post(self):
       username=request.get_json().get('username')
       password=request.get_json().get('password')
       image_url=request.get_json().get('image_url')
       bio=request.get_json().get('bio')

       if username and password:
           new_user=User(
               username=username,
               image_url=image_url,
               bio=bio
           )
           new_user.password_hash=password

           db.session.add(new_user)
           db.session.commit()

           session['user_id']=new_user.id

           return new_user.to_dict(),201
       return {'error':'422 Unprocessable Entity'},422

class CheckSession(Resource):
       def get(self):
        if session["user_id"]:
            user = User.query.filter(User.id == session["user_id"]).first()
            return user.to_dict(), 200
        elif not session["user_id"]:
            return {"message": "Unauthorized request"}, 401

        

class Login(Resource):
    def post(self):
        username = request.get_json().get("username")
        password = request.get_json().get("password")

        user = User.query.filter(User.username == username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        else:
            return {'error': '401 Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session['user_id'] = None
            return {}, 204
        else:
            return {'error': '401 Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        if not session['user_id']:
            return {'message':'Unauthorized'},401
        else:
            user=User.query.filter(User.id==session['user_id']).first()
            if user:
                return [recipe.to_dict() for recipe in user.recipes],200
            else:
                return {'error':'Unauthorized'},401
    def post(self):
        if session["user_id"]:
            request_json = request.get_json()
            title = request_json['title']
            instructions = request_json['instructions']
            minutes_to_complete = request_json['minutes_to_complete']

        # In the post() method, if the user is logged in (if their user_id is in the session object):
            try:
           
                recipe = Recipe(
                    title=title,
                    instructions=instructions,
                    minutes_to_complete=minutes_to_complete,
                    user_id=session['user_id'],
                )

            # Save a new recipe to the database if it is valid. The recipe should belong to the logged in user, and should have title, instructions, and minutes to complete data provided from the request JSON.
                db.session.add(recipe)
                db.session.commit()

            # Return a JSON response with the title, instructions, and minutes to complete data along with a nested user object; and an HTTP status code of 201 (Created).
                return recipe.to_dict(), 201
        
        # If the recipe is not valid:
            except :
            # Return a JSON response with the error messages, and an HTTP status code of 422 (Unprocessable Entity).
                return {'error': '422 Unprocessable Entity'}, 422
        else:
            return {'message': 'Must be logged in to create a recipe'}, 401

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)