from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Usuario(db.Model):    
    __tablename__ = 'usuarios'
    
    id = db.Column(db.Integer, primary_key=True, )
    p_nombre = db.Column(db.String(50), nullable=False)
    s_nombre = db.Column(db.String(50), nullable=True) 
    p_apellido = db.Column(db.String(50), nullable=False)
    s_apellido = db.Column(db.String(50), nullable=False)
    correo = db.Column(db.String(100), unique=True, nullable=False)
    contraseña = db.Column(db.String(128), nullable=False) 

    citas = db.relationship('Cita', backref='usuario', lazy=True)

class Profesor(db.Model):
    __tablename__ = 'profesores'
    
    id = db.Column(db.Integer, primary_key=True)
    p_nombre = db.Column(db.String(50), nullable=False)
    s_nombre = db.Column(db.String(50), nullable=True) 
    p_apellido = db.Column(db.String(50), nullable=False)
    s_apellido = db.Column(db.String(50), nullable=True)
    correo = db.Column(db.String(100), unique=True, nullable=False)
    contraseña = db.Column(db.String(128), nullable=False) 
    matricula = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    dias_disponibles = db.Column(db.String(100), nullable=False)  
    

    citas = db.relationship('Cita', backref='profesor', lazy=True)
    

class Superusuario(db.Model):
    __tablename__ = 'superusuarios'
    
    id = db.Column(db.Integer, primary_key=True)
    p_nombre = db.Column(db.String(50), nullable=False)
    s_nombre = db.Column(db.String(50), nullable=True) 
    p_apellido = db.Column(db.String(50), nullable=False)
    s_apellido = db.Column(db.String(50), nullable=True)
    matricula = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    correo = db.Column(db.String(100), unique=True, nullable=False)
    contraseña = db.Column(db.String(128), nullable=False)
    
    

class Cita(db.Model):
    id_cita = db.Column(db.Integer, primary_key=True, autoincrement=True)
    motivo = db.Column(db.Text, nullable=False)
    fecha_hora = db.Column(db.DateTime, nullable=False)

    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    profesor_id = db.Column(db.Integer, db.ForeignKey('profesores.id'), nullable=False)
    
    