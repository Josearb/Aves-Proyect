from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy.orm import validates
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')  # 'admin', 'specialist', 'dependiente', 'user'
    is_associated = db.Column(db.Boolean, default=False, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    profile_image = db.Column(db.String(255))  # Ruta de la imagen de perfil
    last_login = db.Column(db.DateTime)  # Fecha del último inicio de sesión
    is_active = db.Column(db.Boolean, default=True)  # Para manejar cuentas activas/inactivas
    address = db.Column(db.String(200))  # Nuevo campo para dirección
    
    # Relaciones
    birds = db.relationship('UserBirds', backref='user', lazy=True, cascade='all, delete-orphan')
    awards = db.relationship('Award', backref='user', lazy=True, cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @validates('email')
    def validate_email(self, key, email):
        assert '@' in email, "Email debe contener @"
        return email

    @validates('phone')
    def validate_phone(self, key, phone):
        assert phone.isdigit() and len(phone) >= 8, "Teléfono debe contener solo números y tener al menos 8 dígitos"
        return phone

    @validates('role')
    def validate_role(self, key, role):
        assert role in ['admin', 'specialist', 'dependiente', 'user'], "Rol no válido"
        return role

class BirdCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    parent_category = db.Column(db.String(100))  # Para jerarquías 
    resource_needs = db.Column(db.Text)
    description = db.Column(db.Text)  # Descripción más detallada
    birds = db.relationship('UserBirds', backref='category', lazy=True)

    @validates('name')
    def validate_name(self, key, name):
        assert len(name) >= 3, "Nombre de categoría debe tener al menos 3 caracteres"
        return name

class Award(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contest_name = db.Column(db.String(200), nullable=False)
    award_date = db.Column(db.Date, nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))  # Categoría en la que se ganó el premio
    position = db.Column(db.String)  # Posición obtenida (1ro, 2do, etc.)
    quantity = db.Column(db.Integer, default=1)  # Nueva columna para cantidad de veces obtenido

    @validates('award_date')
    def validate_award_date(self, key, award_date):
        assert award_date is not None, "Fecha de premio no puede ser vacía"
        return award_date
    
    @validates('quantity')
    def validate_quantity(self, key, quantity):
        assert quantity >= 1, "La cantidad debe ser al menos 1"
        return quantity

class UserBirds(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('bird_category.id'), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    food_per_bird = db.Column(db.Float)  # lb por ave por día (asignado por especialista)
    food_type = db.Column(db.String(50))  # Tipo de alimento (Maíz, Trigo, etc.)
    food_process = db.Column(db.String(50))  # Proceso del alimento (grano, molido, etc.)
    notes = db.Column(db.Text)  # Notas adicionales sobre las aves
    export_quantity = db.Column(db.Integer, default=0)  # Cantidad para exportación
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    
    @validates('export_quantity')
    def validate_export_quantity(self, key, export_quantity):
        if export_quantity is not None:
            assert export_quantity <= self.quantity, "La cantidad de exportación no puede ser mayor que la cantidad total"
            assert export_quantity >= 0, "La cantidad de exportación no puede ser negativa"
        return export_quantity

    @property
    def food_required(self):
        return round(self.quantity * (self.food_per_bird or 0), 2)  # Redondeado a 2 decimales

    @validates('quantity')
    def validate_quantity(self, key, quantity):
        assert quantity >= 0, "Cantidad no puede ser negativa"
        return quantity

    @validates('food_per_bird')
    def validate_food_per_bird(self, key, food_per_bird):
        if food_per_bird is not None:
            assert food_per_bird >= 0, "Cantidad de alimento no puede ser negativa"
        return food_per_bird
    
class BirdFoodType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)  # Ej: "Maíz", "Trigo"
    price_per_pound = db.Column(db.Float, nullable=False, default=0.0)  # Precio por libra
    is_active = db.Column(db.Boolean, default=True)  # Para desactivar tipos sin borrar
    last_updated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    last_updated = db.Column(db.DateTime)
    
    @validates('name')
    def validate_name(self, key, name):
        assert len(name) >= 2, "Nombre debe tener al menos 2 caracteres"
        return name
    
    @validates('price_per_pound')
    def validate_price(self, key, price):
        assert price >= 0, "El precio no puede ser negativo"
        return price
    
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notification_type = db.Column(db.String(50))  # 'system', 'food', 'birds', 'award'