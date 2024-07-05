from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates
from config import db, bcrypt

# Create a User model with the following attributes:
class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    serialize_rules = ('-recipes.user', '-_password_hash',)

    id = db.Column(db.Integer, primary_key=True)
    # username that is a String type.
    # validate the user's username to ensure that it is present and unique (no two users can have the same username).
    username = db.Column(db.String, unique=True, nullable=False)
    # _password_hash that is a String type.
    _password_hash = db.Column(db.String)
    # image_url that is a String type.
    image_url = db.Column(db.String)
    # bio that is a String type.
    bio = db.Column(db.String)

    # have many recipes.
    recipes = db.relationship('Recipe', backref='user')

    # incorporate bcrypt to create a secure password. Attempts to access the password_hash should be met with an AttributeError.
    # A hybrid property is a feature provided by the SQLAlchemy library in Python. It allows a method to be accessed as an attribute, providing both the behavior of a property and a method. This means it can be used like an attribute, but it can also contain custom logic like a method.
    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

    def __repr__(self):
        return f'<User {self.username}>'

# Next, create a Recipe model with the following attributes:
class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
   

    id = db.Column(db.Integer, primary_key=True)
    # title that is a String type.
    # title must be present.
    title = db.Column(db.String, nullable=False)
    # instructions that is a String type.
    # instructions must be present and at least 50 characters long.
    instructions = db.Column(db.String, nullable=False)
    # minutes_to_complete that is an Integer type.
    minutes_to_complete = db.Column(db.Integer)
    
    # a recipe belongs to a user.
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if len(instructions) < 50:
            raise ValueError('Instructions must be 50 characters or more.')
        return instructions
    def __repr__(self):
        return f'<Recipe {self.id}: {self.title}>'