
from datetime import datetime, timedelta
from Sign_Docs import db, login_manager, app
from flask_login import UserMixin
import flask.ext.whooshalchemy as wa


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


class User(db.Model, UserMixin):

	__tablename__ = "users"

	id = db.Column(db.Integer, primary_key=True)
	nom = db.Column(db.String(100))
	prenom = db.Column(db.String(100))
	pseudo = db.Column(db.String(80), unique=True, nullable=False)
	email = db.Column(db.String(120), unique=True, nullable=False)
	password = db.Column(db.String(255))
	profile = db.Column(db.String(50),default='default.jpg')

	def __repr__(self):
		return '<User %r %r %r %r >' % (self.nom, self.prenom, self.pseudo, self.email)

class Message(db.Model):

	__tablename__ = "messages"

	id_msg = db.Column(db.Integer, primary_key=True)
	contenu = db.Column(db.Text)	
	signature = db.Column(db.Text)
	fichier = db.Column(db.String(255), default="docs.txt")
	user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
	author = db.relationship('User', backref=db.backref('author', lazy=True))
	date_envoi = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	date_recep = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


	def __repr__(self):
		return '<Message %r %r %r %r %r >' % (self.contenu, self.signature, self.fichier, self.date_envoi, self.date_recep)

class GenerateKeys(db.Model):

	__tablename__ = "clefs"
	__searchable__= ['nom_public_key', 'id_key']

	id_key = db.Column(db.Integer, primary_key=True)
	nom_public_key = db.Column(db.String(100), unique=True)
	nom_private_key = db.Column(db.String(100), unique=True)
	date_create_key = db.Column(db.Date, nullable=False, default=datetime.utcnow)
	date_end_key = db.Column(db.Date, nullable=False, default=timedelta(days=365))

	def __repr__(self):
		return "<GenerateKeys(%r %r %r)>" % (self.id_key,self.nom_public_key, self.nom_private_key)

wa.whoosh_index(app, GenerateKeys)