from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select, delete, or_, update, func
from flask_migrate import Migrate
from models import db, User, BirdCategory, UserBirds, Award, BirdFoodType, Notification
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aves.db'
app.config['SECRET_KEY'] = 'tu_clave_secreta_aqui'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads/profile_images'

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Añadir funciones al contexto de Jinja2
@app.context_processor
def utility_processor():
    def get_unread_notifications_count(user_id):
        return Notification.query.filter_by(user_id=user_id, is_read=False).count()
    
    def get_unread_notifications(user_id):
        return Notification.query.filter_by(user_id=user_id, is_read=False).order_by(Notification.created_at.desc()).all()
    
    return dict(
        get_unread_notifications_count=get_unread_notifications_count,
        get_unread_notifications=get_unread_notifications
    )

def create_default_data():
    with app.app_context():
        # Crear admin si no existe
        if not db.session.execute(select(User).filter_by(username='admin')).scalar():
            admin = User(
                username='admin',
                email='admin@aves.com',
                role='admin',
                full_name='Administrador Principal',
                phone='0000000000',
                is_associated=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("✔ Admin creado: usuario='admin' / contraseña='admin123'")

        # Crear categorías de aves si no existen
        if not db.session.execute(select(BirdCategory)).scalar():
            categories = [
                {'name': 'Canario de color', 'parent': None},
                {'name': 'Canario de canto', 'parent': None},
                {'name': 'Aves exóticas', 'parent': None},
                {'name': 'Psitácidas', 'parent': None},
                {'name': 'Paloma de raza', 'parent': None},
                {'name': 'Paloma de fantasía', 'parent': 'Paloma de raza'},
                {'name': 'Paloma deportiva', 'parent': 'Paloma de raza'},
                {'name': 'Gallináceas', 'parent': None}
            ]
            for cat in categories:
                db.session.add(BirdCategory(
                    name=cat['name'],
                    parent_category=cat['parent'],
                    resource_needs='Requerimientos básicos'
                ))
            db.session.commit()

with app.app_context():
    db.create_all()
    create_default_data()
    
# ----------- Autenticación -----------
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = db.session.execute(
            select(User).filter_by(username=request.form['username'])
        ).scalar()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Usuario o contraseña incorrectos', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if db.session.execute(select(User).filter(or_(
            User.username == request.form['username'],
            User.email == request.form['email']
        ))).scalar():
            flash('Usuario o email ya registrado', 'danger')
            return redirect(url_for('register'))

        user = User(
            username=request.form['username'],
            email=request.form['email'],
            full_name=request.form['full_name'],
            phone=request.form['phone'],
            role='user',
            is_associated=False
        )
        user.set_password(request.form['password'])
        db.session.add(user)
        db.session.commit()
        
        # Notificar al administrador sobre el nuevo registro
        admin = db.session.execute(select(User).filter_by(role='admin')).scalar()
        if admin:
            create_notification(
                user_id=admin.id,
                title="Nuevo registro de usuario",
                message=f"El usuario {user.username} ({user.full_name}) se ha registrado en el sistema.",
                notification_type='system'
            )
        
        flash('Registro exitoso. Inicia sesión', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ----------- Dashboard -----------
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    # Marcar notificaciones como leídas al entrar al dashboard
    mark_notifications_as_read(current_user.id)
    
    if current_user.role == 'admin':
        return redirect(url_for('admin_users'))
    elif current_user.role in ['specialist', 'dependiente']:  
        return redirect(url_for('specialist_users'))
    return redirect(url_for('profile'))

# ----------- Admin Routes -----------
@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        abort(403)
    
    # Obtener parámetros de filtrado
    search_name = request.args.get('name', '').strip()
    award_year = request.args.get('award_year', '').strip()
    award_position = request.args.get('award_position', '').strip()  
    
    # Consulta base
    query = select(User).order_by(User.id)
    
    # Aplicar filtros
    if search_name:
        query = query.where(User.full_name.ilike(f'%{search_name}%'))
    
    if award_year:
        try:
            year = int(award_year)
            start_date = datetime(year, 1, 1)
            end_date = datetime(year + 1, 1, 1)
            
            # Subconsulta para usuarios con premios en ese año
            subquery = select(Award.user_id).where(
                Award.award_date >= start_date,
                Award.award_date < end_date
            ).distinct()
            
            query = query.where(User.id.in_(subquery))
        except ValueError:
            flash('Año de premio no válido', 'warning')
    
    # Nuevo filtro por posición en premios
    if award_position:
        # Subconsulta para usuarios con premios en esa posición
        position_subquery = select(Award.user_id).where(
            Award.position == award_position
        ).distinct()
        
        query = query.where(User.id.in_(position_subquery))
    
    users = db.session.execute(query).scalars()
    
    # Pasar el año actual al template
    current_year = datetime.now().year
    
    return render_template('admin/users.html', 
                         users=users, 
                         search_name=search_name, 
                         award_year=award_year,
                         award_position=award_position,  
                         current_year=current_year)
    
@app.route('/admin/assign_role/<int:user_id>', methods=['POST'])
@login_required
def assign_role(user_id):
    if current_user.role != 'admin':
        abort(403)
    
    user = db.session.get(User, user_id)
    if not user:
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('admin_users'))
    
    try:
        new_role = request.form['role']
        new_association = request.form.get('is_associated') == 'true'
        
        # Notificar al usuario sobre cambios en su rol
        if user.role != new_role or user.is_associated != new_association:
            message = f"El administrador ha actualizado tu perfil:\n"
            if user.role != new_role:
                message += f"- Nuevo rol: {new_role}\n"
            if user.is_associated != new_association:
                status = "Asociado" if new_association else "No asociado"
                message += f"- Estado de asociación: {status}"
            
            create_notification(
                user_id=user.id,
                title="Cambios en tu cuenta",
                message=message,
                notification_type='system'
            )
        
        user.role = new_role
        user.is_associated = new_association
        db.session.commit()
        flash('Configuración de usuario actualizada', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al actualizar: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        abort(403)
    
    user = db.session.get(User, user_id)
    if not user:
        flash('Usuario no encontrado', 'danger')
    else:
        try:
            # Eliminar registros relacionados en el orden correcto
            # 1. Eliminar notificaciones del usuario
            db.session.execute(delete(Notification).where(Notification.user_id == user_id))
            
            # 2. Eliminar aves del usuario
            db.session.execute(delete(UserBirds).where(UserBirds.user_id == user_id))
            
            # 3. Eliminar premios del usuario
            db.session.execute(delete(Award).where(Award.user_id == user_id))
            
            # 4. Finalmente eliminar el usuario
            db.session.delete(user)
            db.session.commit()
            flash('Usuario eliminado correctamente', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error al eliminar usuario: {str(e)}', 'danger')
            app.logger.error(f"Error al eliminar usuario {user_id}: {str(e)}")
    
    return redirect(url_for('admin_users'))

# ----------- Specialist/Dependiente Routes -----------
@app.route('/specialist/users')
@login_required
def specialist_users():
    if current_user.role not in ['specialist', 'dependiente']:
        abort(403)
    
    # Obtener usuarios asociados
    associated_users = db.session.execute(
        select(User).where(User.is_associated == True).order_by(User.full_name)
    ).scalars()
    
    # Preparar datos para la vista
    users_data = []
    for user in associated_users:  # Cambiado de 'user' a 'associated_users' para evitar conflicto
        # Obtener última actualización y cambios
        last_updated = None
        last_quantity_change = 0
        last_food_change = 0.0
        
        if user.birds:
            # Encontrar la última actualización
            last_updated = max(
                (bird.last_updated for bird in user.birds if bird.last_updated),
                default=None
            )
            
            # Calcular cambios
            quantities = [bird.quantity for bird in user.birds]
            if len(quantities) > 1:
                last_quantity_change = quantities[-1] - quantities[-2]
            
            foods = [bird.food_required for bird in user.birds if bird.food_required]
            if len(foods) > 1:
                last_food_change = foods[-1] - foods[-2]
        
        users_data.append({
            'user': user,
            'total_birds': sum(bird.quantity for bird in user.birds),
            'total_food': sum(bird.food_required for bird in user.birds if bird.food_required),
            'last_updated': last_updated,
            'last_quantity_change': last_quantity_change,
            'last_food_change': last_food_change
        })
    
    # Ordenar por usuarios con cambios recientes primero
    users_data.sort(key=lambda x: x['last_updated'] or datetime.min, reverse=True)
    
    return render_template('specialist/users.html', 
                         users=users_data,
                         current_role=current_user.role)

    
@app.route('/specialist/user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def manage_user(user_id):
    # Permitir acceso a especialistas y dependientes
    if current_user.role not in ['specialist', 'dependiente']:
        abort(403)
    
    user = db.session.get(User, user_id)
    if not user or not user.is_associated:
        flash('Usuario no asociado o no encontrado', 'danger')
        return redirect(url_for('specialist_users'))
    
    # Obtener todos los tipos de comida activos
    food_types = db.session.execute(
        select(BirdFoodType).where(BirdFoodType.is_active == True).order_by(BirdFoodType.name)
    ).scalars().all()
    
    # Obtener todas las categorías de aves
    categories = db.session.execute(select(BirdCategory)).scalars().all()
    
    # Obtener nombres de concursos existentes (sin duplicados)
    existing_contests = db.session.execute(
        select(Award.contest_name).distinct().order_by(Award.contest_name)
    ).scalars().all()
    
    # Determinar si está en modo solo lectura (para dependientes)
    read_only = current_user.role == 'dependiente'
    
    if request.method == 'POST' and not read_only:
        # Procesar actualizaciones de comida y nuevos campos
        food_changes = []
        award_added = False
        
        for bird in user.birds:
            # Actualizar cantidad de comida por ave
            food_key = f'food_{bird.id}'
            if food_key in request.form:
                try:
                    old_value = bird.food_per_bird
                    new_value = float(request.form[food_key]) if request.form[food_key] else None
                    
                    if old_value != new_value:
                        bird.food_per_bird = new_value
                        bird.last_updated = datetime.utcnow()
                        food_changes.append(f"{bird.category.name}: {new_value} lb/ave")
                except ValueError:
                    flash(f'Valor inválido para {bird.category.name}', 'danger')
            
            # Actualizar tipo de alimento
            food_type_key = f'food_type_{bird.id}'
            if food_type_key in request.form:
                bird.food_type = request.form[food_type_key]
            
            # Actualizar proceso de alimento (solo si no es Arroz en cáscara)
            food_process_key = f'food_process_{bird.id}'
            if food_process_key in request.form and request.form.get(f'food_type_{bird.id}') != 'Arroz en cáscara':
                bird.food_process = request.form[food_process_key]
            elif request.form.get(f'food_type_{bird.id}') == 'Arroz en cáscara':
                bird.food_process = None
        
        # Procesar nuevo premio (solo si se proporciona el nombre del concurso)
        contest_name = request.form.get('contest_name')
        if contest_name and contest_name != '__other__':
            award_date = request.form.get('award_date')
            position = request.form.get('position')
            
            try:
                award_date_obj = datetime.strptime(award_date, '%Y-%m-%d') if award_date else datetime.utcnow()
                
                if not position:
                    flash('Debe seleccionar un puesto para el premio', 'danger')
                else:
                    award = Award(
                        user_id=user_id,
                        contest_name=contest_name,
                        award_date=award_date_obj,
                        position=position,
                        category=request.form.get('award_category', '')
                    )
                    db.session.add(award)
                    award_added = True
            except ValueError as e:
                flash(f'Error al añadir premio: {str(e)}', 'danger')
        
        try:
            db.session.commit()
            
            # Notificaciones después de confirmar que los cambios se guardaron
            if food_changes:
                # Notificar al usuario
                create_notification(
                    user_id=user.id,
                    title="Actualización de alimentación",
                    message=f"Se han actualizado los requerimientos de comida para tus aves:\n" + 
                           "\n".join(food_changes),
                    notification_type='food'
                )
                
                # Notificar a especialistas y dependientes (excepto al actual)
                staff = db.session.execute(
                    select(User).where(User.role.in_(['specialist', 'dependiente']))
                ).scalars().all()
                
                for member in staff:
                    if member.id != current_user.id:
                        create_notification(
                            user_id=member.id,
                            title=f"Actualización de alimentación - {user.full_name}",
                            message=f"Se han actualizado los requerimientos de comida para {user.full_name}:\n" + 
                                   "\n".join(food_changes),
                            notification_type='food'
                        )
            
            if award_added:
                # Notificar al usuario sobre el nuevo premio
                create_notification(
                    user_id=user.id,
                    title="Nuevo premio registrado",
                    message=f"Se ha registrado un nuevo premio para ti en {contest_name}: {position} lugar",
                    notification_type='award'
                )
                
                # Notificar a especialistas y dependientes
                staff = db.session.execute(
                    select(User).where(User.role.in_(['specialist']))
                ).scalars().all()
                
                for member in staff:
                    if member.id != current_user.id:
                        create_notification(
                            user_id=member.id,
                            title=f"Nuevo premio - {user.full_name}",
                            message=f"{user.full_name} ha ganado un premio en {contest_name}: {position} lugar",
                            notification_type='award'
                        )
            
            flash('Datos actualizados correctamente', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error al guardar los datos: {str(e)}', 'danger')
        
        return redirect(url_for('manage_user', user_id=user_id))
    
    # Calcular total de comida requerida por categoría
    category_totals = {}
    for bird in user.birds:
        if bird.category.name not in category_totals:
            category_totals[bird.category.name] = 0.0
        if bird.food_per_bird and bird.quantity:
            category_totals[bird.category.name] += bird.food_per_bird * bird.quantity
    
    return render_template('specialist/manage_user.html', 
                         user=user,
                         current_role=current_user.role,
                         read_only=read_only,
                         categories=categories,
                         food_types=food_types,
                         existing_contests=existing_contests,
                         category_totals=category_totals,
                         now=datetime.utcnow())

# ----------- User Routes -----------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    categories = db.session.execute(select(BirdCategory)).scalars()
    
    if request.method == 'POST':
        # Actualizar datos personales
        current_user.full_name = request.form['full_name']
        current_user.phone = request.form['phone']
        current_user.address = request.form.get('address', '')  # Usar get() para campos opcionales
        
        # Notificar a especialistas sobre cambios en cantidad de aves
        bird_changes = []
        
        # Primero obtener todas las categorías como lista
        categories_list = list(categories)
        
        for category in categories_list:
            quantity_str = request.form.get(f'category_{category.id}', '0')
            export_str = request.form.get(f'export_{category.id}', '0')
            
            # Validar y convertir valores
            try:
                quantity = int(quantity_str) if quantity_str else 0
                export_quantity = int(export_str) if export_str else 0
            except ValueError:
                flash(f'Valor inválido para {category.name}', 'danger')
                continue
            
            existing = next((b for b in current_user.birds if b.category_id == category.id), None)
            
            if existing:
                # Registrar cambios para notificación
                if existing.quantity != quantity or existing.export_quantity != export_quantity:
                    bird_changes.append(
                        f"{category.name}: {existing.quantity} → {quantity} "
                        f"(Exportación: {existing.export_quantity} → {export_quantity})"
                    )
                
                # Actualizar o eliminar según cantidad
                if quantity >= 0:  # Permitir 0 sin eliminar
                    existing.quantity = quantity
                    existing.export_quantity = min(export_quantity, quantity)
                    existing.last_updated = datetime.utcnow()
                else:
                    db.session.delete(existing)
            elif quantity >= 0:  # Permitir 0 en nuevos registros
                new_bird = UserBirds(
                    user_id=current_user.id,
                    category_id=category.id,
                    quantity=quantity,
                    export_quantity=export_quantity,
                    last_updated=datetime.utcnow()
                )
                db.session.add(new_bird)
                if quantity > 0:
                    bird_changes.append(f"Nuevo registro: {category.name} - {quantity} aves")
        
        # Enviar notificaciones si hay cambios
        if bird_changes:
            staff = db.session.execute(
                select(User).where(User.role.in_(['specialist', 'dependiente']))
            ).scalars().all()
            
            for member in staff:
                create_notification(
                    user_id=member.id,
                    title=f"Actualización de aves - {current_user.full_name}",
                    message="El usuario ha actualizado su registro de aves:\n" + 
                           "\n".join(bird_changes),
                    notification_type='birds'
                )
        
        try:
            db.session.commit()
            flash('Perfil actualizado correctamente', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error al guardar los cambios: {str(e)}', 'danger')
        
        return redirect(url_for('profile'))
    
    # Para GET, necesitamos re-ejecutar la consulta de categorías
    categories = db.session.execute(select(BirdCategory)).scalars()
    return render_template('user/profile.html', categories=categories)

@app.route('/user/awards')
@login_required
def user_awards():
    if current_user.role != 'user':
        abort(403)
    return render_template('user/awards.html',
        awards=db.session.execute(select(Award).filter_by(user_id=current_user.id)).scalars()
    )
    
@app.route('/admin/user_details/<int:user_id>')
@login_required
def user_details(user_id):
    if current_user.role != 'admin':
        abort(403)
    
    user = db.session.get(User, user_id)
    if not user:
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/user_details.html', user=user)

@app.route('/admin/associates_report')
@login_required
def associates_report_view():
    if current_user.role != 'admin':
        abort(403)

    # Obtener todos los usuarios asociados
    associates = db.session.execute(
        select(User).where(User.is_associated == True).order_by(User.full_name)
    ).scalars()

    # Calcular totales por categoría para todos los asociados
    categories = db.session.execute(
        select(BirdCategory.name, 
               func.sum(UserBirds.quantity).label('total_quantity'),
               func.sum(UserBirds.export_quantity).label('total_export'))
        .select_from(UserBirds)
        .join(BirdCategory)
        .join(User)
        .where(User.is_associated == True)
        .group_by(BirdCategory.name)
    ).all()

    # Calcular totales generales
    grand_total = sum(cat.total_quantity or 0 for cat in categories)
    grand_export = sum(cat.total_export or 0 for cat in categories)

    return render_template('admin/associates_report.html',
                         associates=associates,
                         categories=categories,
                         grand_total=grand_total,
                         grand_export=grand_export,
                         now=datetime.utcnow())  
    
@app.route('/specialist/associates_report')
@login_required
def specialist_associates_report():
    if current_user.role != 'specialist':
        abort(403)
    
    # Reutilizamos la misma lógica que para admin
    associates = db.session.execute(
        select(User).where(User.is_associated == True).order_by(User.full_name)
    ).scalars()

    categories = db.session.execute(
        select(BirdCategory.name, 
               func.sum(UserBirds.quantity).label('total_quantity'),
               func.sum(UserBirds.export_quantity).label('total_export'))
        .select_from(UserBirds)
        .join(BirdCategory)
        .join(User)
        .where(User.is_associated == True)
        .group_by(BirdCategory.name)
    ).all()

    grand_total = sum(cat.total_quantity or 0 for cat in categories)
    grand_export = sum(cat.total_export or 0 for cat in categories)

    return render_template('admin/associates_report.html',
                         associates=associates,
                         categories=categories,
                         grand_total=grand_total,
                         grand_export=grand_export,
                         now=datetime.utcnow(),
                         current_role=current_user.role)  # Añadimos el rol actual
    
@app.route('/delete_award/<int:award_id>', methods=['POST'])
@login_required
def delete_award(award_id):
    if current_user.role not in ['admin', 'specialist']:
        abort(403)
    
    award = db.session.get(Award, award_id)
    if not award:
        flash('Premio no encontrado', 'danger')
        return redirect(url_for('specialist_users'))
    
    try:
        user_id = award.user_id
        contest_name = award.contest_name
        position = award.position
        
        db.session.delete(award)
        db.session.commit()
        
        # Notificar al usuario sobre eliminación (excepto si es dependiente)
        user = db.session.get(User, user_id)
        if user and user.role != 'dependiente':
            create_notification(
                user_id=user.id,
                title="Premio eliminado",
                message=f"Se ha eliminado tu premio en {contest_name} ({position} lugar)",
                notification_type='award'
            )
            
        flash('Premio eliminado correctamente', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar premio: {str(e)}', 'danger')
    
    return redirect(url_for('manage_user', user_id=award.user_id))

# ----------- Report Routes -----------
@app.route('/reports/contact')
@login_required
def contact_report():
    if current_user.role not in ['admin', 'specialist']:
        abort(403)
    
    associates = db.session.execute(
        select(User).where(User.is_associated == True).order_by(User.full_name)
    ).scalars()
    
    return render_template('reports/contact_report.html',
                         associates=associates,
                         now=datetime.utcnow())

@app.route('/reports/birds')
@login_required
def birds_report():
    if current_user.role not in ['admin', 'specialist']:
        abort(403)
    
    associates = db.session.execute(
        select(User).where(User.is_associated == True)
        .order_by(User.full_name)
        .options(db.joinedload(User.birds).joinedload(UserBirds.category))
    ).scalars()
    
    return render_template('reports/birds_report.html',
                         associates=associates,
                         now=datetime.utcnow())

@app.route('/reports/awards')
@login_required
def awards_report():
    if current_user.role not in ['admin', 'specialist']:
        abort(403)
    
    # Solución 1: Usar subqueryload en lugar de joinedload para colecciones
    associates = db.session.execute(
        select(User)
        .where(User.is_associated == True)
        .order_by(User.full_name)
        .options(db.subqueryload(User.awards))  # Cambiado a subqueryload
    ).scalars().unique().all()  # Añadido unique() y all()
    
    return render_template('reports/awards_report.html',
                         associates=associates,
                         now=datetime.utcnow())
    
# ---- Rutas para gestión de tipos de comida ----
@app.route('/food_types', methods=['GET', 'POST'])
@login_required
def manage_food_types():
    if current_user.role != 'dependiente':
        abort(403)
    
    if request.method == 'POST':
        # Procesar adición de nuevo tipo
        name = request.form.get('food_name').strip()
        price = float(request.form.get('price'))
        
        try:
            new_food = BirdFoodType(name=name, price_per_pound=price)
            db.session.add(new_food)
            db.session.commit()
            flash(f'Tipo de comida "{name}" agregado correctamente', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error al agregar: {str(e)}', 'danger')
        
        return redirect(url_for('manage_food_types'))
    
    # Obtener todos los tipos de comida
    food_types = db.session.execute(select(BirdFoodType).order_by(BirdFoodType.name)).scalars()
    return render_template('dependiente/food_types.html', food_types=food_types)

@app.route('/update_food_price/<int:food_id>', methods=['POST'])
@login_required
def update_food_price(food_id):
    if current_user.role != 'dependiente':
        abort(403)
    
    food = db.session.get(BirdFoodType, food_id)
    if not food:
        flash('Tipo de comida no encontrado', 'danger')
        return redirect(url_for('manage_food_types'))
    
    try:
        new_price = float(request.form.get('new_price'))
        if food.price_per_pound != new_price:
            # Notificar a especialistas Y dependientes sobre cambio de precio
            staff_members = db.session.execute(
                select(User).where(User.role.in_(['specialist', 'dependiente']))
            ).scalars().all()
            
            for member in staff_members:
                if member.id != current_user.id:  # No notificar al usuario actual
                    create_notification(
                        user_id=member.id,
                        title="Cambio en precio de alimento",
                        message=f"Se ha actualizado el precio de {food.name} a ${new_price:.2f}/lb (por {current_user.full_name})",
                        notification_type='food'
                    )
            
            # Registrar quién hizo el cambio
            food.last_updated_by = current_user.id
            food.price_per_pound = new_price
            food.last_updated = datetime.utcnow()
            
            db.session.commit()
            flash(f'Precio de {food.name} actualizado a ${new_price:.2f}/lb', 'success')
    except ValueError:
        flash('Precio no válido', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al actualizar: {str(e)}', 'danger')
        app.logger.error(f"Error updating food price: {str(e)}")
    
    return redirect(url_for('manage_food_types'))

@app.route('/delete_food_type/<int:food_id>', methods=['POST'])
@login_required
def delete_food_type(food_id):
    if current_user.role != 'dependiente':
        abort(403)
    
    food = db.session.get(BirdFoodType, food_id)
    if not food:
        flash('Tipo de comida no encontrado', 'danger')
    else:
        try:
            db.session.delete(food)
            db.session.commit()
            flash('Tipo de comida eliminado correctamente', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error al eliminar: {str(e)}', 'danger')
    
    return redirect(url_for('manage_food_types'))
    

def create_notification(user_id, title, message, notification_type='system'):
    """Crea una nueva notificación"""
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        notification_type=notification_type
    )
    db.session.add(notification)
    db.session.commit()
    return notification

def get_unread_notifications(user_id):
    """Obtiene notificaciones no leídas para un usuario"""
    return db.session.execute(
        select(Notification)
        .where(Notification.user_id == user_id, Notification.is_read == False)
        .order_by(Notification.created_at.desc())
    ).scalars().all()

def mark_notifications_as_read(user_id):
    """Marca todas las notificaciones como leídas"""
    db.session.execute(
        update(Notification)
        .where(Notification.user_id == user_id, Notification.is_read == False)
        .values(is_read=True)
    )
    db.session.commit()

@app.route('/notifications')
@login_required
def notifications():
    all_notifications = db.session.execute(
        select(Notification)
        .where(Notification.user_id == current_user.id)
        .order_by(Notification.created_at.desc())
    ).scalars().all()
    
    return render_template('notifications.html', notifications=all_notifications)

@app.route('/notifications/read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = db.session.get(Notification, notification_id)
    if notification and notification.user_id == current_user.id:
        notification.is_read = True
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False}), 404

@app.route('/notifications/count')
@login_required
def notification_count():
    count = db.session.execute(
        select(func.count(Notification.id))
        .where(Notification.user_id == current_user.id, Notification.is_read == False)
    ).scalar()
    return jsonify({'count': count})

def create_notification(user_id, title, message, notification_type='system', is_read=False):
    """Crea una nueva notificación"""
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        notification_type=notification_type,
        is_read=is_read,
        created_at=datetime.utcnow()
    )
    db.session.add(notification)
    db.session.commit()
    return notification

if __name__ == '__main__':
    app.run(debug=True, port=5001)