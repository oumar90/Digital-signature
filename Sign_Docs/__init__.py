from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from werkzeug.utils import secure_filename
from flask_avatars import Avatars
# from flask_wtf import CSRFProtect





UPLOAD_FOLDER = 'signs_docs/static/medias/uploads/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'odt', 'docx'])


app = Flask(__name__)
app.config['SECRET_KEY']='b4f8d207f45b6ca20d28a8f11859b737'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqldb://admin:admin123@127.0.0.1/flaskapp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WHOOSH_BASE'] = './Sign_Docs/whoosh'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

avatars = Avatars(app)
# csrf = CSRFProtect(app)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "info"



from Sign_Docs import routes
# wa.whoosh_index(app, GenerateKeys)



