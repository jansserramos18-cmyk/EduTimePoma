import os
import re
import functools
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from Models import db, Usuario, Profesor, Superusuario, Cita
from sqlalchemy import or_
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///EduTime.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cambia-esto-en-produccion')


app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True   
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  



csrf = CSRFProtect(app)


limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:;"
    )
    return response

db.init_app(app)
Session(app)

with app.app_context():
    db.create_all()


def es_correo_valido(correo):
    patron = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'
    return re.match(patron, correo) is not None

def es_contraseña_fuerte(pw):
    """Mínimo 8 caracteres, al menos una letra y un número."""
    return len(pw) >= 8 and re.search(r'[A-Za-z]', pw) and re.search(r'\d', pw)

def campos_vacios(*args):
    return any(not v or not str(v).strip() for v in args)


def login_usuario_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash("Debes iniciar sesión primero.", "warning")
            return redirect(url_for('login_usuario'))
        return f(*args, **kwargs)
    return decorated

def login_maestro_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if 'maestro_id' not in session:
            flash("Debes iniciar sesión como maestro.", "warning")
            return redirect(url_for('login_maestro'))
        return f(*args, **kwargs)
    return decorated

def superusuario_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_superuser'):
            flash("Acceso denegado. Solo superusuarios.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def home():
    return render_template('base.html')


@app.route('/login_usuario', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login_usuario():
    if request.method == 'POST':
        correo = request.form.get('correo', '').strip()
        contraseña = request.form.get('contraseña', '')

        if campos_vacios(correo, contraseña):
            flash("Completa todos los campos.", "warning")
            return render_template('inicio_de_sesion_como_usuario.html')

        # SQLAlchemy usa consultas parametrizadas por defecto: seguro contra SQL Injection
        usuario = Usuario.query.filter_by(correo=correo).first()

        if usuario and check_password_hash(usuario.contraseña, contraseña):
            session.clear()
            session['user_id'] = usuario.id
            session['role'] = 'usuario'
            session['nombre'] = usuario.p_nombre
            return redirect(url_for('dashboard_usuario'))
        else:
            # Mensaje genérico: no revela si el correo existe o no
            flash("Credenciales incorrectas.", "danger")

    return render_template('inicio_de_sesion_como_usuario.html')


@app.route('/login_maestro', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login_maestro():
    if request.method == 'POST':
        correo = request.form.get('correo', '').strip()
        contraseña = request.form.get('contraseña', '')

        if campos_vacios(correo, contraseña):
            flash("Completa todos los campos.", "warning")
            return render_template('inicio_de_sesion_como_maestro.html')

        maestro = Profesor.query.filter_by(correo=correo).first()

        if maestro and check_password_hash(maestro.contraseña, contraseña):
            session.clear()
            session['maestro_id'] = maestro.id
            session['role'] = 'maestro'
            session['nombre'] = maestro.p_nombre
            if maestro.is_superuser:
                session['is_superuser'] = True
            return redirect(url_for('dashboard_maestro'))
        else:
            flash("Credenciales incorrectas.", "danger")

    return render_template('inicio_de_sesion_como_maestro.html')


@app.route('/login_superusuario', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login_superusuario():
    if request.method == 'POST':
        correo = request.form.get('correo', '').strip()
        contraseña = request.form.get('contraseña', '')

        if campos_vacios(correo, contraseña):
            flash("Completa todos los campos.", "warning")
            return render_template('inicio_de_sesion_como_superusuario.html')

        superusuario = Superusuario.query.filter_by(correo=correo).first()

        if superusuario and check_password_hash(superusuario.contraseña, contraseña):
            session.clear()
            session['superuser_id'] = superusuario.id
            session['role'] = 'superusuario'
            session['nombre'] = superusuario.p_nombre
            session['is_superuser'] = True
            return redirect(url_for('dashboard_superusuario'))
        else:
            flash("Credenciales incorrectas.", "danger")

    return render_template('inicio_de_sesion_como_superusuario.html')


@app.route('/registro_usuario', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def registro_usuario():
    if request.method == 'POST':
        nombre     = request.form.get('nombre', '').strip()
        s_nombre   = request.form.get('s_nombre', '').strip()
        apellido_p = request.form.get('apellido_p', '').strip()
        apellido_m = request.form.get('apellido_m', '').strip()
        correo     = request.form.get('correo', '').strip()
        contraseña = request.form.get('contraseña', '')

        if campos_vacios(nombre, apellido_p, apellido_m, correo, contraseña):
            flash("Todos los campos obligatorios deben estar completos.", "warning")
            return render_template('registro_usuario.html')

        if not es_correo_valido(correo):
            flash("El formato del correo no es válido.", "warning")
            return render_template('registro_usuario.html')

        if not es_contraseña_fuerte(contraseña):
            flash("La contraseña debe tener al menos 8 caracteres, una letra y un número.", "warning")
            return render_template('registro_usuario.html')

        if Usuario.query.filter_by(correo=correo).first():
            flash("El correo ya está registrado.", "warning")
            return redirect(url_for('login_usuario'))

        nuevo_usuario = Usuario(
            p_nombre=nombre,
            s_nombre=s_nombre,
            p_apellido=apellido_p,
            s_apellido=apellido_m,
            correo=correo,
            contraseña=generate_password_hash(contraseña)   # Hash seguro
        )

        try:
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash("¡Usuario registrado con éxito!", "success")
            return redirect(url_for('login_usuario'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error registro usuario: {e}")
            flash("Hubo un error al registrar. Intenta de nuevo.", "danger")

    return render_template('registro_usuario.html')


@app.route('/registro_maestro', methods=['GET', 'POST'])
@superusuario_required
def registro_maestro():
    if request.method == 'POST':
        nombre     = request.form.get('nombre', '').strip()
        s_nombre   = request.form.get('s_nombre', '').strip()
        apellido_p = request.form.get('apellido_p', '').strip()
        apellido_m = request.form.get('apellido_m', '').strip()
        correo     = request.form.get('correo', '').strip()
        contraseña = request.form.get('contraseña', '')
        matricula  = request.form.get('matricula', '').strip()
        dias       = request.form.getlist('dias')

        if campos_vacios(nombre, apellido_p, correo, contraseña, matricula):
            flash("Todos los campos obligatorios deben estar completos.", "warning")
            return render_template('registro_maestro.html')

        if not es_correo_valido(correo):
            flash("El formato del correo no es válido.", "warning")
            return render_template('registro_maestro.html')

        if not es_contraseña_fuerte(contraseña):
            flash("La contraseña debe tener al menos 8 caracteres, una letra y un número.", "warning")
            return render_template('registro_maestro.html')

        # Validaciones de unicidad ANTES de crear el objeto
        if Profesor.query.filter_by(correo=correo).first():
            flash("El correo ya está registrado como maestro.", "warning")
            return redirect(url_for('login_maestro'))

        if Profesor.query.filter_by(matricula=matricula).first():
            flash("La matrícula ya está registrada.", "warning")
            return redirect(url_for('registro_maestro'))

        username = f"{nombre}{apellido_p}{matricula}".lower().replace(" ", "")
        if Profesor.query.filter_by(username=username).first():
            flash("El nombre de usuario generado ya existe.", "warning")
            return redirect(url_for('registro_maestro'))

        nuevo_maestro = Profesor(
            p_nombre=nombre,
            s_nombre=s_nombre,
            p_apellido=apellido_p,
            s_apellido=apellido_m,
            correo=correo,
            contraseña=generate_password_hash(contraseña),  # Hash seguro
            matricula=matricula,
            username=username,
            dias_disponibles=",".join(dias)
        )

        try:
            db.session.add(nuevo_maestro)
            db.session.commit()
            flash("¡Maestro registrado! Por favor inicia sesión.", "success")
            return redirect(url_for('login_maestro'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error registro maestro: {e}")
            flash("Error al registrar maestro.", "danger")

    return render_template('registro_maestro.html')


@app.route('/registro_superusuario', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def registro_superusuario():
    CLAVE_ADMIN = os.environ.get('ADMIN_REGISTRATION_KEY', '')

    if request.method == 'POST':
        clave_ingresada = request.form.get('clave_admin', '')

        if not CLAVE_ADMIN or clave_ingresada != CLAVE_ADMIN:
            flash("Clave de administrador incorrecta o no configurada.", "danger")
            return render_template('registro_superusuario.html')

        p_nombre   = request.form.get('p_nombre', '').strip()
        s_nombre   = request.form.get('s_nombre', '').strip()
        p_apellido = request.form.get('p_apellido', '').strip()
        s_apellido = request.form.get('s_apellido', '').strip()
        correo     = request.form.get('correo', '').strip()
        contraseña = request.form.get('contraseña', '')
        matricula  = request.form.get('matricula', '').strip()
        username   = request.form.get('username', '').strip()

        if campos_vacios(p_nombre, p_apellido, correo, contraseña, matricula, username):
            flash("Todos los campos obligatorios deben estar completos.", "warning")
            return render_template('registro_superusuario.html')

        if not es_correo_valido(correo):
            flash("El formato del correo no es válido.", "warning")
            return render_template('registro_superusuario.html')

        if not es_contraseña_fuerte(contraseña):
            flash("La contraseña debe tener al menos 8 caracteres, una letra y un número.", "warning")
            return render_template('registro_superusuario.html')

        if Superusuario.query.filter_by(correo=correo).first():
            flash("El correo ya está registrado.", "warning")
            return redirect(url_for('registro_superusuario'))
        if Superusuario.query.filter_by(matricula=matricula).first():
            flash("La matrícula ya está registrada.", "warning")
            return redirect(url_for('registro_superusuario'))
        if Superusuario.query.filter_by(username=username).first():
            flash("El nombre de usuario ya existe.", "warning")
            return redirect(url_for('registro_superusuario'))

        nuevo_superusuario = Superusuario(
            p_nombre=p_nombre,
            s_nombre=s_nombre,
            p_apellido=p_apellido,
            s_apellido=s_apellido,
            correo=correo,
            contraseña=generate_password_hash(contraseña),  # Hash seguro
            matricula=matricula,
            username=username
        )

        try:
            db.session.add(nuevo_superusuario)
            db.session.commit()
            flash("¡Superusuario registrado exitosamente!", "success")
            return redirect(url_for('login_superusuario'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error registro superusuario: {e}")
            flash("Error al registrar superusuario.", "danger")

    return render_template('registro_superusuario.html')


@app.route('/dashboard_usuario')
@login_usuario_required
def dashboard_usuario():
    citas = Cita.query.filter_by(usuario_id=session['user_id']).join(Profesor).add_columns(
        Cita.id_cita,
        Cita.motivo,
        Cita.fecha_hora,
        Profesor.p_nombre.label('profesor_nombre'),
        Profesor.p_apellido.label('profesor_apellido'),
        Profesor.correo.label('profesor_correo')
    ).all()
    return render_template('dashboard_usuario.html', nombre=session.get('nombre'), citas=citas, ahora=datetime.now())


@app.route('/dashboard_maestro')
@login_maestro_required
def dashboard_maestro():
    citas = Cita.query.filter_by(profesor_id=session['maestro_id']).join(Usuario).add_columns(
        Cita.id_cita,
        Cita.motivo,
        Cita.fecha_hora,
        Usuario.p_nombre.label('usuario_nombre'),
        Usuario.p_apellido.label('usuario_apellido'),
        Usuario.correo.label('usuario_correo')
    ).all()
    return render_template('dashboard_maestro.html', nombre=session.get('nombre'), citas=citas, ahora=datetime.now())


@app.route('/dashboard_superusuario')
@superusuario_required
def dashboard_superusuario():
    citas    = Cita.query.order_by(Cita.fecha_hora.asc()).all()
    usuarios = Usuario.query.order_by(Usuario.p_nombre.asc()).all()
    maestros = Profesor.query.order_by(Profesor.p_nombre.asc()).all()
    return render_template(
        'dashboard_superusuario_real.html',
        citas=citas,
        usuarios=usuarios,
        maestros=maestros,
        total_usuarios=len(usuarios),
        total_maestros=len(maestros),
        total_citas=Cita.query.count(),
        ahora=datetime.now()
    )


@app.route('/agendar_cita', methods=['GET', 'POST'])
@login_usuario_required
def agendar_cita():
    if request.method == 'POST':
        motivo         = request.form.get('motivo', '').strip()
        fecha_hora_str = request.form.get('fecha_hora', '')

        try:
            profesor_id = int(request.form.get('profesor_id'))
        except (TypeError, ValueError):
            flash("Profesor no válido.", "danger")
            return redirect(url_for('agendar_cita'))

        if campos_vacios(motivo, fecha_hora_str):
            flash("Completa todos los campos.", "warning")
            return redirect(url_for('agendar_cita'))

        try:
            fecha_hora = datetime.strptime(fecha_hora_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("La fecha y hora no tienen el formato correcto.", "danger")
            return redirect(url_for('agendar_cita'))

        if fecha_hora < datetime.now():
            flash("No puedes agendar una cita en el pasado.", "warning")
            return redirect(url_for('agendar_cita'))


        profesor = db.session.get(Profesor, profesor_id)
        if not profesor:
            flash("El profesor seleccionado no existe.", "danger")
            return redirect(url_for('agendar_cita'))

        nueva_cita = Cita(
            motivo=motivo,
            fecha_hora=fecha_hora,
            usuario_id=session['user_id'],
            profesor_id=profesor_id
        )

        try:
            db.session.add(nueva_cita)
            db.session.commit()
            flash("¡Cita agendada!", "success")
            return redirect(url_for('dashboard_usuario'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error al agendar cita: {e}")
            flash("Error al agendar la cita.", "danger")

    profesores = Profesor.query.all()
    return render_template('agendar_cita.html', profesores=profesores)


@app.route('/mis_citas')
@login_usuario_required
def mis_citas():
    citas = Cita.query.filter_by(usuario_id=session['user_id']).join(Profesor).add_columns(
        Cita.id_cita,
        Cita.motivo,
        Cita.fecha_hora,
        Profesor.p_nombre.label('profesor_nombre'),
        Profesor.p_apellido.label('profesor_apellido'),
        Profesor.correo.label('profesor_correo')
    ).all()
    return render_template('mis_citas.html', citas=citas, current_time=datetime.now())


@app.route('/editar_cita/<int:cita_id>', methods=['GET', 'POST'])
@login_usuario_required
def editar_cita(cita_id):
    cita = Cita.query.get_or_404(cita_id)

    if cita.usuario_id != session['user_id']:
        flash("No tienes permiso para editar esta cita.", "danger")
        return redirect(url_for('mis_citas'))

    if cita.fecha_hora < datetime.now():
        flash("No puedes editar una cita que ya ha pasado.", "warning")
        return redirect(url_for('mis_citas'))

    if request.method == 'POST':
        motivo         = request.form.get('motivo', '').strip()
        fecha_hora_str = request.form.get('fecha_hora', '')

        try:
            profesor_id = int(request.form.get('profesor_id'))
        except (TypeError, ValueError):
            flash("Profesor no válido.", "danger")
            return redirect(url_for('editar_cita', cita_id=cita_id))

        try:
            fecha_hora = datetime.strptime(fecha_hora_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("La fecha y hora no tienen el formato correcto.", "danger")
            return redirect(url_for('editar_cita', cita_id=cita_id))

        if fecha_hora < datetime.now():
            flash("No puedes agendar una cita en el pasado.", "warning")
            return redirect(url_for('editar_cita', cita_id=cita_id))

        profesor = db.session.get(Profesor, profesor_id)
        if not profesor:
            flash("El profesor seleccionado no existe.", "danger")
            return redirect(url_for('editar_cita', cita_id=cita_id))

        try:
            cita.profesor_id = profesor_id
            cita.motivo      = motivo
            cita.fecha_hora  = fecha_hora
            db.session.commit()
            flash("¡Cita actualizada exitosamente!", "success")
            return redirect(url_for('mis_citas'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error al editar cita: {e}")
            flash("Error al actualizar la cita.", "danger")

    profesores = Profesor.query.all()
    return render_template('editar_cita.html', cita=cita, profesores=profesores)


@app.route('/editar_cita_maestro/<int:cita_id>', methods=['GET', 'POST'])
@login_maestro_required
def editar_cita_maestro(cita_id):
    cita = Cita.query.get_or_404(cita_id)

    if cita.profesor_id != session['maestro_id']:
        flash("No tienes permiso para editar esta cita.", "danger")
        return redirect(url_for('dashboard_maestro'))

    if cita.fecha_hora < datetime.now():
        flash("No puedes editar una cita que ya ha pasado.", "warning")
        return redirect(url_for('dashboard_maestro'))

    if request.method == 'POST':
        motivo         = request.form.get('motivo', '').strip()
        fecha_hora_str = request.form.get('fecha_hora', '')

        try:
            fecha_hora = datetime.strptime(fecha_hora_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("La fecha y hora no tienen el formato correcto.", "danger")
            return redirect(url_for('editar_cita_maestro', cita_id=cita_id))

        if fecha_hora < datetime.now():
            flash("No puedes mover la cita al pasado.", "warning")
            return redirect(url_for('editar_cita_maestro', cita_id=cita_id))

        try:
            cita.fecha_hora = fecha_hora
            cita.motivo     = motivo
            db.session.commit()
            flash("¡Cita actualizada exitosamente!", "success")
            return redirect(url_for('dashboard_maestro'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error al editar cita maestro: {e}")
            flash("Error al actualizar la cita.", "danger")

    usuario = db.session.get(Usuario, cita.usuario_id)
    return render_template('editar_cita_maestro.html', cita=cita, usuario=usuario)


@app.route('/cancelar_cita_superusuario/<int:cita_id>', methods=['POST'])
@superusuario_required
def cancelar_cita_superusuario(cita_id):
    cita = Cita.query.get_or_404(cita_id)
    try:
        db.session.delete(cita)
        db.session.commit()
        flash("¡Cita cancelada exitosamente!", "success")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al cancelar cita: {e}")
        flash("Error al cancelar la cita.", "danger")
    return redirect(url_for('dashboard_superusuario'))


@app.route('/eliminar_usuario/<int:usuario_id>', methods=['POST'])
@superusuario_required
def eliminar_usuario(usuario_id):
    usuario = Usuario.query.get_or_404(usuario_id)
    try:
        Cita.query.filter_by(usuario_id=usuario.id).delete()
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuario eliminado correctamente.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al eliminar usuario: {e}")
        flash(f'Error al eliminar usuario.', 'danger')
    return redirect(url_for('dashboard_superusuario'))


@app.route('/eliminar_profesor/<int:profesor_id>', methods=['POST'])
@superusuario_required
def eliminar_profesor(profesor_id):
    profesor = Profesor.query.get_or_404(profesor_id)
    try:
        Cita.query.filter_by(profesor_id=profesor.id).delete()
        db.session.delete(profesor)
        db.session.commit()
        flash('Profesor eliminado correctamente.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al eliminar profesor: {e}")
        flash('Error al eliminar profesor.', 'danger')
    return redirect(url_for('dashboard_superusuario'))


@app.route('/eliminar_cuenta', methods=['POST'])
def eliminar_cuenta():
    role = session.get('role')

    if role == 'usuario' and 'user_id' in session:
        usuario = db.session.get(Usuario, session['user_id'])
        if usuario:
            Cita.query.filter_by(usuario_id=usuario.id).delete()
            db.session.delete(usuario)
            db.session.commit()
        session.clear()
        flash('Tu cuenta de usuario ha sido eliminada correctamente.', 'success')
        return redirect(url_for('home'))

    if role == 'maestro' and 'maestro_id' in session:
        profesor = db.session.get(Profesor, session['maestro_id'])
        if profesor:
            Cita.query.filter_by(profesor_id=profesor.id).delete()
            db.session.delete(profesor)
            db.session.commit()
        session.clear()
        flash('Tu cuenta de maestro ha sido eliminada correctamente.', 'success')
        return redirect(url_for('home'))

    flash('No se encontró ninguna sesión activa para eliminar.', 'warning')
    return redirect(url_for('home'))


@app.route('/editar_perfil_usuario', methods=['GET', 'POST'])
@login_usuario_required
def editar_perfil_usuario():
    usuario = db.session.get(Usuario, session['user_id'])

    if request.method == 'POST':
        nombre            = request.form.get('nombre', '').strip()
        s_nombre          = request.form.get('s_nombre', '').strip()
        apellido_p        = request.form.get('apellido_p', '').strip()
        apellido_m        = request.form.get('apellido_m', '').strip()
        correo            = request.form.get('correo', '').strip()
        contraseña_actual = request.form.get('contraseña_actual', '')
        nueva_contraseña  = request.form.get('nueva_contraseña', '')

        if campos_vacios(nombre, apellido_p, apellido_m, correo, contraseña_actual):
            flash("Completa todos los campos obligatorios.", "warning")
            return redirect(url_for('editar_perfil_usuario'))

        if not check_password_hash(usuario.contraseña, contraseña_actual):
            flash("La contraseña actual es incorrecta.", "danger")
            return redirect(url_for('editar_perfil_usuario'))

        if not es_correo_valido(correo):
            flash("El formato del correo no es válido.", "warning")
            return redirect(url_for('editar_perfil_usuario'))

        if correo != usuario.correo:
            if Usuario.query.filter_by(correo=correo).first():
                flash("El correo ya está registrado por otro usuario.", "warning")
                return redirect(url_for('editar_perfil_usuario'))

        if nueva_contraseña and not es_contraseña_fuerte(nueva_contraseña):
            flash("La nueva contraseña debe tener al menos 8 caracteres, una letra y un número.", "warning")
            return redirect(url_for('editar_perfil_usuario'))

        try:
            usuario.p_nombre  = nombre
            usuario.s_nombre  = s_nombre
            usuario.p_apellido = apellido_p
            usuario.s_apellido = apellido_m
            usuario.correo    = correo
            if nueva_contraseña:
                usuario.contraseña = generate_password_hash(nueva_contraseña)
            db.session.commit()
            session['nombre'] = nombre
            flash("¡Perfil actualizado exitosamente!", "success")
            return redirect(url_for('dashboard_usuario'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error al editar perfil usuario: {e}")
            flash("Error al actualizar el perfil.", "danger")

    return render_template('editar_perfil_usuario.html', usuario=usuario)


@app.route('/editar_perfil_maestro', methods=['GET', 'POST'])
@login_maestro_required
def editar_perfil_maestro():
    maestro = db.session.get(Profesor, session['maestro_id'])

    if request.method == 'POST':
        nombre            = request.form.get('nombre', '').strip()
        s_nombre          = request.form.get('s_nombre', '').strip()
        apellido_p        = request.form.get('apellido_p', '').strip()
        apellido_m        = request.form.get('apellido_m', '').strip()
        correo            = request.form.get('correo', '').strip()
        contraseña_actual = request.form.get('contraseña_actual', '')
        nueva_contraseña  = request.form.get('nueva_contraseña', '')

        if campos_vacios(nombre, apellido_p, correo, contraseña_actual):
            flash("Completa todos los campos obligatorios.", "warning")
            return redirect(url_for('editar_perfil_maestro'))

        if not check_password_hash(maestro.contraseña, contraseña_actual):
            flash("La contraseña actual es incorrecta.", "danger")
            return redirect(url_for('editar_perfil_maestro'))

        if not es_correo_valido(correo):
            flash("El formato del correo no es válido.", "warning")
            return redirect(url_for('editar_perfil_maestro'))

        if correo != maestro.correo:
            if Profesor.query.filter_by(correo=correo).first():
                flash("El correo ya está registrado por otro maestro.", "warning")
                return redirect(url_for('editar_perfil_maestro'))

        if nueva_contraseña and not es_contraseña_fuerte(nueva_contraseña):
            flash("La nueva contraseña debe tener al menos 8 caracteres, una letra y un número.", "warning")
            return redirect(url_for('editar_perfil_maestro'))

        try:
            maestro.p_nombre  = nombre
            maestro.s_nombre  = s_nombre
            maestro.p_apellido = apellido_p
            maestro.s_apellido = apellido_m
            maestro.correo    = correo
            if nueva_contraseña:
                maestro.contraseña = generate_password_hash(nueva_contraseña)
            db.session.commit()
            session['nombre'] = nombre
            flash("¡Perfil actualizado exitosamente!", "success")
            return redirect(url_for('dashboard_maestro'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error al editar perfil maestro: {e}")
            flash("Error al actualizar el perfil.", "danger")

    return render_template('editar_perfil_maestro.html', maestro=maestro)



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    # debug=False en producción. Usa una variable de entorno para controlarlo.
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode)