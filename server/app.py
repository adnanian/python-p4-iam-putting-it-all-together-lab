#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def check_if_logged_in():
    endpoint_whitelist = ['signup', 'login', 'check_session']
    if (not session.get('user_id')) and request.endpoint not in endpoint_whitelist:
        return {'error': 'Unauthorized'}, 401

class Signup(Resource):
    def post(self):
        """
        try:
            username = request.get_json().get('username')
            password = request.get_json().get('password')
            password_confirmation = request.get_json().get('password_confirmation')
            if (username and password) and (password == password_confirmation):
                new_user = User(
                    username=username,
                    image_url=request.get_json().get('image_url'),
                    bio=request.get_json().get('bio')
                )   
                new_user.password_hash = password
                db.session.add(new_user)
                db.session.commit()
                session['user_id'] = new_user.id
                return new_user.to_dict(), 201
            #else:
                #raise IntegrityError("Invalid or mismatching fields entered.")
        except IntegrityError as e:
            return {'error': '422 Unprocessable Entity'}, 422
            """
        username = request.get_json().get('username')
        password = request.get_json().get('password')
        password_confirmation = request.get_json().get('password_confirmation')
        image_url=request.get_json().get('image_url')
        bio=request.get_json().get('bio')
        new_user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )
        new_user.password_hash = password
        try:
            db.session.add(new_user)
            #new_user.authenticate(password_confirmation)
            db.session.commit()
            session['user_id'] = new_user.id
            return new_user.to_dict(), 201
        except IntegrityError as e:
            return {'error': '422 Unprocessable Entity'}, 422

class CheckSession(Resource):
    def get(self):
        if user := User.query.filter_by(id=session['user_id']).first():
            return user.to_dict(), 200
        return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        user = User.query.filter_by(username=request.get_json()['username']).first()
        if user and user.authenticate(request.get_json()['password']):
            session['user_id'] = user.id
            return user.to_dict(), 200
        else:
            return {'error': '401 Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        session['user_id'] = None
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        user = User.query.filter_by(id=session['user_id']).first()
        recipes = [recipe.to_dict() for recipe in user.recipes]
        return recipes, 200

    def post(self):
        json = request.get_json()
        new_recipe = Recipe(
            title=json.get('title'),
            instructions=json.get('instructions'),
            minutes_to_complete=json.get('minutes_to_complete'),
            user_id=session['user_id']
        )
        try:
            db.session.add(new_recipe)
            db.session.commit()
            return new_recipe.to_dict(), 201
        except IntegrityError as e:
            return {'error': 'Unprocessable Entity'}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)