from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_session import Session  
from Models import db, Usuario, Profesor, Superusuario, Cita
from sqlalchemy import or_
from datetime import datetime

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///EduTime.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'El_mayor_acto_de_amor_que_ha_recibido_el_mundo_es_que_el__Señor_dio_su_vida_por_nosotros'


app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True


db.init_app(app)
Session(app)  

with app.app_context():
    db.create_all()  

@app.route('/')
def home():
    return render_template('base.html')

@app.route('/login_usuario', methods=['GET', 'POST'])
def login_usuario():
    if request.method == 'POST':
        correo = request.form.get('correo')
        contraseña = request.form.get('contraseña')

        usuario = Usuario.query.filter_by(correo=correo).first()

        if usuario and usuario.contraseña == contraseña:
            session['user_id'] = usuario.id
            session['role'] = 'usuario'
            session['nombre'] = usuario.p_nombre
            return redirect(url_for('dashboard_usuario'))
        else:
            flash("Correo o contraseña incorrectos", "danger")

    return render_template('inicio_de_sesion_como_usuario.html')

@app.route('/login_maestro', methods=['GET', 'POST'])
def login_maestro():
    if request.method == 'POST':
        correo = request.form.get('correo')
        contraseña = request.form.get('contraseña')

        maestro = Profesor.query.filter_by(correo=correo).first()

        if maestro and maestro.contraseña == contraseña:
            session['maestro_id'] = maestro.id
            session['role'] = 'maestro'
            session['nombre'] = maestro.p_nombre
            if maestro.is_superuser:
                session['is_superuser'] = True
            return redirect(url_for('dashboard_maestro'))
        else:
            flash("Correo o contraseña incorrectos, o no estás registrado como docente. Hable con el equipo de coordinación para la autorización de su registro como docente.", "danger")

    return render_template('inicio_de_sesion_como_maestro.html')

@app.route('/login_superusuario', methods=['GET', 'POST'])
def login_superusuario():
    if request.method == 'POST':
        correo = request.form.get('correo')
        contraseña = request.form.get('contraseña')

        superusuario = Superusuario.query.filter_by(correo=correo).first()

        if superusuario and superusuario.contraseña == contraseña:
            session['superuser_id'] = superusuario.id
            session['role'] = 'superusuario'
            session['nombre'] = superusuario.p_nombre
            session['is_superuser'] = True
            return redirect(url_for('dashboard_superusuario'))
        else:
            flash("Correo o contraseña incorrectos", "danger")

    return render_template('inicio_de_sesion_como_superusuario.html')

@app.route('/registro_usuario', methods=['GET', 'POST'])
def registro_usuario():
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        s_nombre = request.form.get('s_nombre')
        apellido_p = request.form.get('apellido_p')
        apellido_m = request.form.get('apellido_m')
        correo = request.form.get('correo')
        contraseña = request.form.get('contraseña')

        nuevo_usuario = Usuario(
            p_nombre=nombre,
            s_nombre=s_nombre,
            p_apellido=apellido_p,
            s_apellido=apellido_m,
            correo=correo,
            contraseña=contraseña
        )

        try:
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash("¡Usuario Registrado con Éxito!", "success")
            return redirect(url_for('login_usuario'))
        except Exception as e:
            db.session.rollback()
            flash(f"Hubo un error: {e}", "danger")

    return render_template('registro_usuario.html')

@app.route('/registro_maestro', methods=['GET', 'POST'])
def registro_maestro():
    if not session.get('is_superuser'):
        flash("Acceso denegado. Solo superusuarios pueden registrar maestros.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        nombre = request.form.get('nombre')
        s_nombre = request.form.get('s_nombre')
        apellido_p = request.form.get('apellido_p')
        apellido_m = request.form.get('apellido_m')
        correo = request.form.get('correo')
        contraseña = request.form.get('contraseña')
        matricula = request.form.get('matricula')
        dias = request.form.getlist('dias') 

        username = f"{nombre}{apellido_p}{matricula}".lower().replace(" ", "")
        dias_disponibles = ",".join(dias)

        nuevo_maestro = Profesor(
            p_nombre=nombre,
            s_nombre=s_nombre,
            p_apellido=apellido_p,
            s_apellido=apellido_m,
            correo=correo,
            contraseña=contraseña,
            matricula=matricula,
            username=username,
            dias_disponibles=dias_disponibles
        )

        existe_el_correo = Profesor.query.filter_by(correo=correo).first()
        existe_la_matricula = Profesor.query.filter_by(matricula=matricula).first()
        existe_el_username = Profesor.query.filter_by(username=username).first()

        if existe_el_correo:
            flash("El correo ya está registrado como maestro. Inicia sesión.", "warning")
            return redirect(url_for('login_maestro'))
        if existe_la_matricula:
            flash("La matrícula ya está registrada.", "warning")
            return redirect(url_for('registro_maestro'))
        if existe_el_username:
            flash("El nombre de usuario generado ya existe.", "warning")
            return redirect(url_for('registro_maestro'))

        try:
            db.session.add(nuevo_maestro)
            db.session.commit()
            flash("¡Maestro registrado exitosamente!", "success")
            return redirect(url_for('dashboard_superusuario'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error al registrar maestro: {e}", "danger")

    return render_template('registro_maestro.html')

@app.route('/registro_superusuario', methods=['GET', 'POST'])
def registro_superusuario():
    
    if request.method == 'POST':
        p_nombre = request.form.get('p_nombre')
        s_nombre = request.form.get('s_nombre')
        p_apellido = request.form.get('p_apellido')
        s_apellido = request.form.get('s_apellido')
        correo = request.form.get('correo')
        contraseña = request.form.get('contraseña')
        matricula = request.form.get('matricula')
        username = request.form.get('username')

        nuevo_superusuario = Superusuario(
            p_nombre=p_nombre,
            s_nombre=s_nombre,
            p_apellido=p_apellido,
            s_apellido=s_apellido,
            correo=correo,
            contraseña=contraseña,
            matricula=matricula,
            username=username
        )

        existe_correo = Superusuario.query.filter_by(correo=correo).first()
        existe_matricula = Superusuario.query.filter_by(matricula=matricula).first()
        existe_username = Superusuario.query.filter_by(username=username).first()

        if existe_correo:
            flash("El correo ya está registrado como superusuario.", "warning")
            return redirect(url_for('registro_superusuario'))
        if existe_matricula:
            flash("La matrícula ya está registrada.", "warning")
            return redirect(url_for('registro_superusuario'))
        if existe_username:
            flash("El nombre de usuario ya existe.", "warning")
            return redirect(url_for('registro_superusuario'))

        try:
            db.session.add(nuevo_superusuario)
            db.session.commit()
            flash("¡Superusuario registrado exitosamente!", "success")
            return redirect(url_for('login_superusuario'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error al registrar superusuario: {e}", "danger")

    return render_template('registro_superusuario.html')

@app.route('/dashboard_usuario')
def dashboard_usuario():
    if 'user_id' not in session:
        return redirect(url_for('login_usuario'))

    citas = Cita.query.filter_by(usuario_id=session['user_id']).join(Profesor).add_columns(
        Cita.id_cita,
        Cita.motivo,
        Cita.fecha_hora,
        Profesor.p_nombre.label('profesor_nombre'),
        Profesor.p_apellido.label('profesor_apellido'),
        Profesor.correo.label('profesor_correo')
    ).all()

    return render_template('dashboard_usuario.html', nombre=session.get('nombre'), citas=citas, ahora=datetime.now())

@app.route('/dashboard_superusuario', methods=['GET', 'POST'])
def dashboard_superusuario():
    if 'superuser_id' not in session:
        return redirect(url_for('login_superusuario'))
    
    if request.method == 'POST':
        p_nombre = request.form.get('p_nombre')
        s_nombre = request.form.get('s_nombre')
        p_apellido = request.form.get('p_apellido')
        s_apellido = request.form.get('s_apellido')
        matricula = request.form.get('matricula')
        username = request.form.get('username')
        correo = request.form.get('correo')
        contraseña = request.form.get('contraseña')

        existe_matricula = Superusuario.query.filter_by(matricula=matricula).first()
        existe_username = Superusuario.query.filter_by(username=username).first()
        existe_correo = Superusuario.query.filter_by(correo=correo).first()
        if existe_matricula:
            flash("La matrícula ya está registrada.", "warning")
            return redirect(url_for('dashboard_superusuario'))
        if existe_username:
            flash("El nombre de usuario ya existe.", "warning")
            return redirect(url_for('dashboard_superusuario'))
        if existe_correo:
            flash("El correo ya está registrado.", "warning")
            return redirect(url_for('dashboard_superusuario'))

        nuevo_superusuario = Superusuario(
            p_nombre=p_nombre,
            s_nombre=s_nombre,
            p_apellido=p_apellido,
            s_apellido=s_apellido,
            matricula=matricula,
            username=username,
            correo=correo,
            contraseña=contraseña
        )
        
        citas = Cita.query.filter_by(usuario_id=session['user_id']).join(Profesor).add_columns(
            Cita.id_cita,
            Cita.motivo,
            Cita.fecha_hora,
            Profesor.p_nombre.label('profesor_nombre'),
            Profesor.p_apellido.label('profesor_apellido'),
            Profesor.correo.label('profesor_correo')
        ).all()

        try:
            db.session.add(nuevo_superusuario)
            db.session.commit()
            flash("¡Superusuario registrado exitosamente!", "success")
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error al registrar: {e}", "danger")

    return render_template('dashboard_superusuario.html')

@app.route('/agendar_cita', methods=['GET', 'POST'])
def agendar_cita():
    if 'user_id' not in session:
        return redirect(url_for('login_usuario'))

    if request.method == 'POST':
        profesor_id = request.form.get('profesor_id')
        motivo = request.form.get('motivo')
        fecha_hora_str = request.form.get('fecha_hora')

        try:
            fecha_hora = datetime.strptime(fecha_hora_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("La fecha y hora no están bien", "danger")
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
            flash(f"Error al agendar: {e}", "danger")

    profesores = Profesor.query.all()
    return render_template('agendar_cita.html', profesores=profesores)

@app.route('/mis_citas')
def mis_citas():
    if 'user_id' not in session:
        return redirect(url_for('login_usuario'))

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
def editar_cita(cita_id):
    if 'user_id' not in session:
        return redirect(url_for('login_usuario'))
    
    cita = Cita.query.get_or_404(cita_id)
    

    if cita.usuario_id != session['user_id']:
        flash("No tienes permiso para editar esta cita", "danger")
        return redirect(url_for('mis_citas'))

    if cita.fecha_hora < datetime.now():
        flash("No puedes editar una cita que ya ha pasado", "warning")
        return redirect(url_for('mis_citas'))
    
    if request.method == 'POST':
        profesor_id = request.form.get('profesor_id')
        motivo = request.form.get('motivo')
        fecha_hora_str = request.form.get('fecha_hora')
        
        try:
            fecha_hora = datetime.strptime(fecha_hora_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("La fecha y hora no están bien", "danger")
            return redirect(url_for('editar_cita', cita_id=cita_id))
        
        try:
            cita.profesor_id = profesor_id
            cita.motivo = motivo
            cita.fecha_hora = fecha_hora
            db.session.commit()
            flash("¡Cita actualizada exitosamente!", "success")
            return redirect(url_for('mis_citas'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error al actualizar: {e}", "danger")
    
    profesores = Profesor.query.all()
    return render_template('editar_cita.html', cita=cita, profesores=profesores)

@app.route('/cancelar_cita_superusuario/<int:cita_id>', methods=['POST'])
def cancelar_cita_superusuario(cita_id):
    if not session.get('is_superuser'):
        return redirect(url_for('home'))

    cita = Cita.query.get_or_404(cita_id)

    try:
        db.session.delete(cita)
        db.session.commit()
        flash("¡Cita cancelada exitosamente!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al cancelar: {e}", "danger")
    
    return redirect(url_for('dashboard_superusuario'))

@app.route('/editar_cita_maestro/<int:cita_id>', methods=['GET', 'POST'])
def editar_cita_maestro(cita_id):
    if 'maestro_id' not in session:
        return redirect(url_for('login_maestro'))
    
    cita = Cita.query.get_or_404(cita_id)
    

    if cita.profesor_id != session['maestro_id']:
        flash("No tienes permiso para editar esta cita", "danger")
        return redirect(url_for('dashboard_maestro'))
    

    if cita.fecha_hora < datetime.now():
        flash("No puedes editar una cita que ya ha pasado", "warning")
        return redirect(url_for('dashboard_maestro'))
    
    if request.method == 'POST':
        motivo = request.form.get('motivo')
        fecha_hora_str = request.form.get('fecha_hora')
        
        try:
            fecha_hora = datetime.strptime(fecha_hora_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("La fecha y hora no están bien", "danger")
            return redirect(url_for('editar_cita_maestro', cita_id=cita_id))
        
        try:
            cita.fecha_hora = fecha_hora
            cita.motivo = motivo
            db.session.commit()
            flash("¡Cita actualizada exitosamente!", "success")
            return redirect(url_for('dashboard_maestro'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error al actualizar: {e}", "danger")
    
    usuario = Usuario.query.get(cita.usuario_id)
    return render_template('editar_cita_maestro.html', cita=cita, usuario=usuario)

@app.route('/logout')
def logout():
    session.clear() 
    return redirect(url_for('home'))

@app.route('/eliminar_cuenta', methods=['POST'])
def eliminar_cuenta():
    role = session.get('role')

    if role == 'usuario' and 'user_id' in session:
        usuario = Usuario.query.get(session['user_id'])
        if usuario:
        
            Cita.query.filter_by(usuario_id=usuario.id).delete()
            db.session.delete(usuario)
            db.session.commit()
        session.clear()
        flash('Tu cuenta de usuario ha sido eliminada correctamente.', 'success')
        return redirect(url_for('home'))

    if role == 'maestro' and 'maestro_id' in session:
        profesor = Profesor.query.get(session['maestro_id'])
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
def editar_perfil_usuario():
    if 'user_id' not in session:
        return redirect(url_for('login_usuario'))

    usuario = Usuario.query.get(session['user_id'])

    if request.method == 'POST':
        nombre = request.form.get('nombre')
        s_nombre = request.form.get('s_nombre')
        apellido_p = request.form.get('apellido_p')
        apellido_m = request.form.get('apellido_m')
        correo = request.form.get('correo')
        contraseña_actual = request.form.get('contraseña_actual')
        nueva_contraseña = request.form.get('nueva_contraseña')

        
        if not usuario.contraseña == contraseña_actual:
            flash("La contraseña actual es incorrecta", "danger")
            return redirect(url_for('editar_perfil_usuario'))

        
        if correo != usuario.correo:
            existing = Usuario.query.filter_by(correo=correo).first()
            if existing:
                flash("El correo ya está registrado por otro usuario", "warning")
                return redirect(url_for('editar_perfil_usuario'))

        try:
            usuario.p_nombre = nombre
            usuario.s_nombre = s_nombre
            usuario.p_apellido = apellido_p
            usuario.s_apellido = apellido_m
            usuario.correo = correo

            if nueva_contraseña:
                usuario.contraseña = nueva_contraseña

            db.session.commit()
            session['nombre'] = nombre  
            flash("¡Perfil actualizado exitosamente!", "success")
            return redirect(url_for('dashboard_usuario'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error al actualizar perfil: {e}", "danger")

    return render_template('editar_perfil_usuario.html', usuario=usuario)

@app.route('/editar_perfil_maestro', methods=['GET', 'POST'])
def editar_perfil_maestro():
    if 'maestro_id' not in session:
        return redirect(url_for('login_maestro'))

    maestro = Profesor.query.get(session['maestro_id'])

    if request.method == 'POST':
        nombre = request.form.get('nombre')
        s_nombre = request.form.get('s_nombre')
        apellido_p = request.form.get('apellido_p')
        apellido_m = request.form.get('apellido_m')
        correo = request.form.get('correo')
        contraseña_actual = request.form.get('contraseña_actual')
        nueva_contraseña = request.form.get('nueva_contraseña')

        if not maestro.contraseña == contraseña_actual:
            flash("La contraseña actual es incorrecta", "danger")
            return redirect(url_for('editar_perfil_maestro'))

        if correo != maestro.correo:
            existing = Profesor.query.filter_by(correo=correo).first()
            if existing:
                flash("El correo ya está registrado por otro maestro", "warning")
                return redirect(url_for('editar_perfil_maestro'))

        try:
            maestro.p_nombre = nombre
            maestro.s_nombre = s_nombre
            maestro.p_apellido = apellido_p
            maestro.s_apellido = apellido_m
            maestro.correo = correo

            if nueva_contraseña:
                maestro.contraseña = nueva_contraseña

            db.session.commit()
            session['nombre'] = nombre  
            flash("¡Perfil actualizado exitosamente!", "success")
            return redirect(url_for('dashboard_maestro'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error al actualizar perfil: {e}", "danger")

    return render_template('editar_perfil_maestro.html', maestro=maestro)

@app.route('/dashboard_maestro')
def dashboard_maestro():
    if 'maestro_id' not in session:
        return redirect(url_for('login_maestro'))

    citas = Cita.query.filter_by(profesor_id=session['maestro_id']).join(Usuario).add_columns(
        Cita.id_cita,
        Cita.motivo,
        Cita.fecha_hora,
        Usuario.p_nombre.label('usuario_nombre'),
        Usuario.p_apellido.label('usuario_apellido'),
        Usuario.correo.label('usuario_correo')
    ).all()

    return render_template('dashboard_maestro.html', nombre=session.get('nombre'), citas=citas, ahora=datetime.now())

if __name__ == '__main__':
    app.run(debug=True)



