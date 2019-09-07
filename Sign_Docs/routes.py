from flask import (render_template, redirect, request, url_for, flash, current_app)
from Sign_Docs import db, bcrypt, app, ALLOWED_EXTENSIONS
from flask_login import login_user, logout_user, login_required, current_user
from Sign_Docs.models import User, Message, GenerateKeys
from oudjirasign import *
import os
import secrets



def save_file(fichier):
	_,file_extention = os.path.splitext(fichier.filename)
	nom_fichier = fichier.filename
	path_fichier = os.path.join(current_app.root_path, "static/medias/uploads/", nom_fichier)
	fichier.save(path_fichier)
	return nom_fichier

def save_photo(photo):
	hash_fichier = secrets.token_urlsafe(6)
	_, file_extention = os.path.splitext(photo.filename)
	nom_fichier = hash_fichier + file_extention
	path_fichier = os.path.join(current_app.root_path, "static/images/", nom_fichier)
	photo.save(path_fichier)
	return nom_fichier

def allowed_photo(filename):
	return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/')
@app.route('/home')
def home():
	return render_template("home.html")


@app.route('/register', methods=['GET', 'POST'])
def register():

	if request.method == 'POST':
		nom = request.form.get('nom')
		prenom = request.form.get('prenom')
		pseudo = request.form.get('pseudo')
		password = request.form.get('password')
		confirm_password = request.form.get('password_repeat')

		if len(password) == 0:
			flash("Tous les champs sont requis", 'danger')
			return redirect(url_for("register"))
		else:
			if password == confirm_password:
				user = User.query.filter_by(pseudo=pseudo).first()
				if user:
					flash("le pseudo est déjà pris, veillez choisir un autre svp!", "danger")
					return redirect(url_for('register'))
				email = User.query.filter_by(email=request.form.get('email')).first()
				if email:
					flash("l'emil est déjà pris, veillez choisir un autre svp!", "danger")
					return redirect(url_for('register'))

				email = request.form.get('email')
				hashed_password = bcrypt.generate_password_hash(password)

				user = User(nom=nom,prenom=prenom,pseudo=pseudo,email=email,password=hashed_password)
				db.session.add(user)
				db.session.commit()

				flash("Votre compte a été cré avec succès", "success")

				return redirect(url_for('login'))
			else:
				flash("Les mot de passe ne correspondent pas", "danger")
				return render_template("register.html")

				
	return render_template("register.html")


# Route qui gère la connexion (login)
@app.route('/login', methods=['GET', 'POST'])
def login():

	if request.method == 'POST':
		email = request.form.get('email')
		password = request.form.get('password')

		user = User.query.filter_by(email=email).first()
		
		if user and  bcrypt.check_password_hash(user.password, password):
			login_user(user)
			
			# flash("Vous êtes connecté avec succès", "success")
			next = request.args.get('next')
			return redirect(next or url_for('profile'))

		flash("pseudo ou mot de passe incorrect, veillez verifier et réeseyer", "danger")
		return redirect(url_for('login'))
	
	return render_template('login.html')

# Route qui gère la déconnexion
@app.route('/logout', methods=['GET', 'POST'])
def logout():
	logout_user()
	return redirect(url_for('login'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required 
def profile():
	user_profile = User.query.all()

	profile = url_for('static', filename='images/' + current_user.profile)

	if request.method == 'GET':
		return render_template("profile.html", profile=profile, user_profile=user_profile)

	else:

		# user = User.query.filter_by(pseudo=request.form.get('pseudo')).first()
		# if user:
		# 	flash("le pseudo est déjà pris, veillez choisir un autre svp!", "danger")
		# 	return redirect(url_for('profile'))
		# email = User.query.filter_by(email=request.form.get('email')).first()
		# if email:
		# 	flash("l'email est déjà pris, veillez choisir un autre svp!", "danger")
		# 	return redirect(url_for('profile'))
			
		img_profile = request.files.get('image_profile')
	

		current_user.pseudo = request.form.get('pseudo')
		current_user.nom = request.form.get('nom')
		current_user.prenom = request.form.get('prenom')
		current_user.email = request.form.get('email')
	
		
		if img_profile and allowed_photo(img_profile.filename):

			photo = save_photo(img_profile)
			current_user.profile = photo

			db.session.commit()
			flash("Votre compte a été mis à jour.", "success")
			return render_template("profile.html", profile=profile, user_profile=user_profile)
		else:
			flash("Veillez choisir une image svp", "danger")
		
			return render_template("profile.html", profile=profile, user_profile=user_profile)

# Route qui permet de generer les clés
@app.route('/generer_clef', methods=['GET', 'POST'])
@login_required
def generer_clef():

	if request.method == 'GET':
		return render_template("generer_clef.html")

	else:
		priv,pub = generatersakeys()
		pub=pub.decode('utf-8')
		priv=priv.decode('utf-8')

		# alea_string = secrets.token_urlsafe(4)

		try:
			private_key_name = current_user.pseudo + "private.pem"
			public_key_name = current_user.pseudo + "public.pem"
			private_name = open("Sign_Docs/static/keys/" + private_key_name, "w")
			private_name.write(priv)
			private_name.close()	

			public_nale = open("Sign_Docs/static/keys/" + public_key_name, "w")
			public_nale.write(pub)
			public_nale.close()

			date = request.form.get('date')

			new_key = GenerateKeys(nom_public_key=public_key_name,nom_private_key=private_key_name, date_end_key=date)
			db.session.add(new_key)
			db.session.commit()
			

			flash("Votre paire de clef a été générée avec succès.", "success")
			return render_template("generer_clef.html", pub=pub, priv=priv)
		except :
			flash("Vous avez déjà une paire de clef.", "info")
			return  redirect(url_for("afficher_clef"))


@app.route('/envoyer_message', methods=['GET', 'POST'])
@login_required
def envoyer_message():
	user = User.query.all()

	if request.method == 'GET':
		return render_template("envoyer_message.html", user=user)
	else:

		description = request.form.get('description')
		email= request.form.get('email')
		f = request.files.get('customFile')

		if f and allowed_photo(f.filename):
			customFile = save_file(f)

			# customFile = request.files['customFile']
			user1 = User.query.filter_by(email=email).first()
			print(user1)
			private_path = request.files['privatekey']

			if private_path:

				try:
					privatekey = private_path.read()
					privatekey1 = importPrivateKey(privatekey)
					signature = signer(description, privatekey1)
					
				

					if user1.email:
						print("Avant")
						message = Message(contenu=description,user_id=user1.id,\
							signature=signature,fichier=customFile, author=current_user)
						print("Apres req")
						db.session.add(message)
						db.session.commit()
						flash("Votre message a été envoyé avec succès", "success")
						return render_template("envoyer_message.html", user=user)
					else:
						flash("Votre message n'a été envoyé, verifier l'utilisateur", "info")

						return render_template("envoyer_message", user=user)
				except:
					flash("Votre clé n'est pas valide.", "danger")
			else:
				flash("Vous n'avez pas selectionner la clef privée", "info")
				return render_template("envoyer_message.html", user=user)
		else:
			flash("Ce type de fichier n'est accepté. Veillez choisir un fichier valide", "info")
			render_template("envoyer_message.html", user=user)

	return render_template("envoyer_message.html", user=user)

@app.route('/recevoirmsg')
@login_required
def recevoirmsg():
	messages = Message.query.order_by(Message.date_envoi.desc())
	return render_template('recevoirmsg.html', messages=messages)

@app.route('/recevoir_message', methods=['GET', 'POST'])
@login_required
def recevoir_message():
	# On recupère tous les messages par date d'envoi le plus recent
	messages = Message.query.order_by(Message.date_envoi.desc())
	
	nombre_message = 0
	for i in messages:
		nombre_message +=1
	
	return render_template("recevoir_message.html", messages=messages, nombre_message=nombre_message)
	
# Route qui gère un la verification de l'integrité d'un message
@app.route('/recevoir_message_un/<int:id_msg>', methods=['GET', 'POST'])
@login_required
def recevoir_message_un(id_msg):

	# On recupère le message par leur id
	message = Message.query.get(id_msg)

	if request.method == 'GET':
		return render_template("recevoir_message_un.html", message=message)

	# Si on est en mode post, on recupère la clef publique et le message
	publickey = request.files['publickey']
	contenu = request.form['contenu']
	if publickey:
		publickey = publickey.read()
		
		
	# On test le champs de clef publique, si c'est vide on léve une exception
	else:
		flash("Tous les champs doivent être remplis! ", "danger")
		return render_template("recevoir_message_un.html", message=message)

	# On essaie de verifier la signature
	try:

		#  On appelle la fonction importPublickey() pour importer la clef public
		# Et la focntion verifier(contenu, publickey, signature) pour verifier la signature.
		publickey = importPublicKey(publickey)
		
		verify = verifier(contenu, publickey, message.signature)
		
		if verify:
			flash("La signature est valide.", "success")
			return render_template("recevoir_message_un.html", message=message)
		else:
			flash("La signature est invalide!", "danger")
			return render_template("recevoir_message_un.html", message=message)

	# Dans le cas où on arrive pas à importer la clef publique
	except : 
		flash("Veillez entrer une clef publique valide!", "danger")
		return render_template("recevoir_message_un.html", message=message)



@app.route('/afficher_clef', methods=['GET', 'POST'])
@login_required
def afficher_clef():
	from datetime import datetime
	clefs = GenerateKeys.query.order_by(GenerateKeys.date_create_key.desc())

	# for k in clefs:
	# 	past = k.date_end_key - k.date_create_key
	# 	present = datetime.now()
		
	
	if request.method == "GET":
		return render_template('afficher_clef.html',clefs=clefs)
	return render_template("afficher_clef.html", clefs=clefs)

@app.route('/afficher_clef/delete', methods=['POST'])
@login_required
def delete_key():

	public_key = request.form['public_key']
	key = GenerateKeys.query.filter_by(nom_public_key=public_key).first()

	if current_user.pseudo not in key.nom_public_key:
		flash("Vous n'avez pas le droit de supprimer ce clef", "danger")
		return redirect(url_for("afficher_clef"))
	else:
		db.session.delete(key)
		db.session.commit()
		flash('Votre clef a été bien supprimée', 'success')
		return redirect(url_for('afficher_clef'))

@app.route('/search')
def search():
	word = request.args.get('query')
	clefs = GenerateKeys.query.filter_by(nom_public_key=word).all()
	if len(clefs)==0:
		flash(word + " n'existe pas!", 'info');
		return render_template("afficher_clef.html", clefs=clefs)
	return render_template("afficher_clef.html", clefs=clefs)

@app.route('/delete_message/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_message(id):

	id = request.args.get('id')
	msg = Message.query.filter_by(id_msg=id).first()
	db.session.delete(msg)
	db.session.commit()
	flash('Le message a été supprimé.', 'success')
	return redirect(url_for('recevoir_message'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
	return render_template("forgot-password.html")


# gerere la date de footer
@app.context_processor
def inject_now():
	from datetime import datetime
	return {'now': datetime.utcnow()}

@app.route('/demande_certificat')
@login_required
def demande_certificat():
	
	return render_template("demande_certificat.html")



@app.route('/archives')
@login_required
def archive():
	archives = Message.query.all()
	return render_template('archive.html', archives=archives)


@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html")


















