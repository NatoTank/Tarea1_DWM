from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse 
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timedelta, timezone, date, time
from enum import Enum
import io 
import random

# --- LIBRERÍAS DE SEGURIDAD ---
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- ¡NUEVOS IMPORTS PARA LA BASE DE DATOS! ---
# (¡AÑADIMOS 'func'!)
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, DateTime, ForeignKey, Enum as SAEnum, Table, func
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.ext.declarative import declarative_base

# --- CONFIGURACIÓN DE LA BASE DE DATOS ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./chocomania.db" 

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- 1. DEFINICIONES DE ENUMS ---

class Roles(str, Enum):
    cliente = "cliente"
    administrador = "administrador"
    cocinero = "cocinero"
    repartidor = "repartidor"

class EstadoPedido(str, Enum):
    pendiente_de_pago = "pendiente_de_pago"
    pagado = "pagado"
    en_preparacion = "en_preparacion"
    despachado = "despachado"
    entregado = "entregado" 
    rechazado = "rechazado"
    cancelado = "cancelado"

class TipoNotificacion(str, Enum):
    pedido_recibido = "pedido_recibido"
    pedido_despachado = "pedido_despachado"
    retraso_entrega = "retraso_entrega"

class EstadoSeguimiento(str, Enum):
    en_camino = "En Camino"
    entregado = "Entregado"
    problema_reportado = "Problema Reportado"

class TipoDocumento(str, Enum):
    boleta = "boleta"
    factura = "factura"

# --- 2. MODELOS DE BASE DE DATOS (SQLAlchemy) ---

pedido_items_tabla = Table('pedido_items', Base.metadata,
    Column('pedido_id', Integer, ForeignKey('pedidos.id'), primary_key=True),
    Column('producto_id', Integer, ForeignKey('productos.id'), primary_key=True),
    Column('cantidad', Integer),
    Column('precio_en_el_momento', Float)
)

class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    rol = Column(SAEnum(Roles), default=Roles.cliente)
    nombre = Column(String, nullable=True)
    direccion = Column(String, nullable=True)
    comuna = Column(String, nullable=True)
    telefono = Column(String, nullable=True)
    recibirPromos = Column(Boolean, default=True)
    
    pedidos = relationship("PedidoDB", back_populates="dueño")

class ProductoDB(Base):
    __tablename__ = "productos"
    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, index=True)
    descripcion = Column(String, nullable=True)
    precio = Column(Float)
    tipo = Column(String)
    stock = Column(Integer)
    activo = Column(Boolean, default=True)
    
    pedidos = relationship("PedidoDB", secondary=pedido_items_tabla, back_populates="productos")

class PedidoDB(Base):
    __tablename__ = "pedidos"
    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey('usuarios.id'))
    total = Column(Float)
    estado = Column(SAEnum(EstadoPedido), default=EstadoPedido.pendiente_de_pago)
    fecha_creacion = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    dueño = relationship("UsuarioDB", back_populates="pedidos")
    productos = relationship("ProductoDB", secondary=pedido_items_tabla, back_populates="pedidos")
    seguimiento = relationship("SeguimientoDB", back_populates="pedido", uselist=False)
    notificaciones = relationship("NotificacionDB", back_populates="pedido")
    documento = relationship("DocumentoDB", back_populates="pedido", uselist=False)

class NotificacionDB(Base):
    __tablename__ = "notificaciones"
    id = Column(Integer, primary_key=True, index=True)
    pedido_id = Column(Integer, ForeignKey('pedidos.id'))
    tipo = Column(SAEnum(TipoNotificacion))
    mensaje = Column(String)
    hora_estimada = Column(String, nullable=True) 
    fecha_envio = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    pedido = relationship("PedidoDB", back_populates="notificaciones")

class SeguimientoDB(Base):
    __tablename__ = "seguimientos"
    id = Column(Integer, primary_key=True, index=True)
    pedido_id = Column(Integer, ForeignKey('pedidos.id'), unique=True)
    estado = Column(SAEnum(EstadoSeguimiento), default=EstadoSeguimiento.en_camino)
    hora_estimada_llegada = Column(String, nullable=True)
    repartidor_asignado = Column(String, nullable=True)
    lat = Column(Float, nullable=True)
    lng = Column(Float, nullable=True)
    
    pedido = relationship("PedidoDB", back_populates="seguimiento")

class DocumentoDB(Base):
    __tablename__ = "documentos"
    id = Column(Integer, primary_key=True, index=True)
    pedido_id = Column(Integer, ForeignKey('pedidos.id'))
    fecha = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    tipo = Column(SAEnum(TipoDocumento))
    total = Column(Float)
    rut = Column(String, nullable=True)
    razon_social = Column(String, nullable=True)
    
    pedido = relationship("PedidoDB", back_populates="documento", foreign_keys=[pedido_id])


# --- 3. SCHEMAS (DTOs de Pydantic) ---

class UsuarioCreate(BaseModel):
    email: str
    contraseña: str

class DatosPersonalesUpdate(BaseModel):
    nombre: str
    direccion: str
    comuna: str
    telefono: str

class SuscripcionInput(BaseModel):
    recibirPromos: bool

class CambioContraseñaInput(BaseModel):
    contraseña_actual: str
    nueva_contraseña: str

class RolUpdate(BaseModel):
    nuevo_rol: Roles

class ProductoBase(BaseModel):
    nombre: str
    descripcion: Optional[str] = None
    precio: float
    tipo: str
    stock: int
    
class ProductoCreate(ProductoBase):
    pass

class ProductoUpdate(BaseModel):
    nombre: Optional[str] = None
    descripcion: Optional[str] = None
    precio: Optional[float] = None
    tipo: Optional[str] = None
    stock: Optional[int] = None
    activo: Optional[bool] = None

class PedidoItemInput(BaseModel):
    producto_id: int
    cantidad: int

class PedidoCreateInput(BaseModel):
    items: List[PedidoItemInput]

class EnviarNotificacionInput(BaseModel):
    pedido_id: int
    tipo: TipoNotificacion
    mensaje_opcional: Optional[str] = None

class ActualizarNotificacionInput(BaseModel):
    mensaje_nuevo: str
    nueva_hora_estimada: Optional[time] = None

class Ubicacion(BaseModel):
    lat: float
    lng: float

class ConfirmarEntregaInput(BaseModel):
    confirmacion_texto: str = "Entregado OK" 

class FacturaInput(BaseModel):
    rut: str
    razon_social: str

class VentasPorHora(BaseModel):
    hora: int
    total: float

class DashboardVentas(BaseModel):
    total_acumulado: float
    ticket_promedio: float
    top_productos: List[str]
    ventas_por_hora: List[VentasPorHora]

class DashboardPedidoActivo(BaseModel):
    id: str
    cliente: str
    estado: str
    tiempo_estimado: str
    encargado: str

# (Schemas para SALIDA de datos - con orm_mode)
class ConfigORM:
    orm_mode = True 
    # from_attributes = True # (Si usas Pydantic 2.x)

class UsuarioSchema(BaseModel):
    id: int
    email: str
    rol: Roles
    nombre: Optional[str] = None
    direccion: Optional[str] = None
    comuna: Optional[str] = None
    telefono: Optional[str] = None
    recibirPromos: bool
    
    class Config(ConfigORM): pass

class ProductoSchema(ProductoBase):
    id: int
    activo: bool
    class Config(ConfigORM): pass

class PedidoSchema(BaseModel):
    id: int
    usuario_id: int
    total: float
    estado: EstadoPedido
    fecha_creacion: datetime
    
    class Config(ConfigORM): pass

class SeguimientoSchema(BaseModel):
    pedido_id: int 
    estado: EstadoSeguimiento
    hora_estimada_llegada: Optional[str] = None
    repartidor_asignado: Optional[str] = None
    ubicacion_actual: Optional[Ubicacion] = None
    class Config(ConfigORM): pass

class NotificacionSchema(BaseModel):
    id: int
    pedido_id: int
    tipo: TipoNotificacion
    mensaje: str
    hora_estimada: Optional[str] = None
    fecha_envio: datetime
    class Config(ConfigORM): pass

class DocumentoSchema(BaseModel):
    id: int
    pedido_id: int
    fecha: datetime
    tipo: TipoDocumento
    total: float
    rut: Optional[str] = None
    razon_social: Optional[str] = None
    class Config(ConfigORM): pass

# --- 4. CONFIGURACIÓN DE SEGURIDAD ---
SECRET_KEY = "tu-clave-secreta-super-dificil-de-adivinar"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# --- 5. FUNCIONES HELPER DE SEGURIDAD ---
def verificar_contraseña(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def hashear_contraseña(password: str) -> str:
    return pwd_context.hash(password)

def crear_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta: expire = datetime.now(timezone.utc) + expires_delta
    else: expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# --- 6. FUNCIONES DE AUTENTICACIÓN Y BBDD ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_usuario_by_email(db: Session, email: str) -> Optional[UsuarioDB]:
    return db.query(UsuarioDB).filter(UsuarioDB.email == email).first()

def get_usuario_by_id(db: Session, user_id: int) -> Optional[UsuarioDB]:
    return db.query(UsuarioDB).filter(UsuarioDB.id == user_id).first()

def get_producto_by_id(db: Session, producto_id: int) -> Optional[ProductoDB]:
    return db.query(ProductoDB).filter(ProductoDB.id == producto_id).first()

def get_pedido_by_id(db: Session, pedido_id: int) -> Optional[PedidoDB]:
    return db.query(PedidoDB).filter(PedidoDB.id == pedido_id).first()

def get_notificacion_by_pedido_id(db: Session, pedido_id: int) -> List[NotificacionDB]:
    return db.query(NotificacionDB).filter(NotificacionDB.pedido_id == pedido_id).all()

def get_seguimiento_by_pedido_id(db: Session, pedido_id: int) -> Optional[SeguimientoDB]:
    return db.query(SeguimientoDB).filter(SeguimientoDB.pedido_id == pedido_id).first()

def autenticar_usuario(db: Session, email: str, contraseña: str) -> Optional[UsuarioDB]:
    usuario = get_usuario_by_email(db, email)
    if not usuario or not verificar_contraseña(contraseña, usuario.hashed_password):
        return None
    return usuario

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UsuarioDB:
    credentials_exception = HTTPException(status_code=401, detail="Credenciales inválidas")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
    except JWTError:
        raise credentials_exception
    usuario = get_usuario_by_email(db, email) 
    if usuario is None: raise credentials_exception
    return usuario

async def get_current_admin_user(current_user: UsuarioDB = Depends(get_current_user)) -> UsuarioDB:
    if current_user.rol != Roles.administrador:
        raise HTTPException(status_code=403, detail="Requiere permisos de administrador")
    return current_user

async def get_current_repartidor_user(current_user: UsuarioDB = Depends(get_current_user)) -> UsuarioDB:
    if current_user.rol != Roles.repartidor:
        raise HTTPException(status_code=403, detail="Acción solo para repartidores")
    return current_user


# --- 7. CREA LA APP ---
app = FastAPI(
    title="Chocomanía API (con BBDD)",
    description="API para el sistema de E-commerce Chocomanía"
)

# ¡ESTA LÍNEA CREA EL ARCHIVO 'chocomania.db' Y LAS TABLAS!
Base.metadata.create_all(bind=engine)

# --- 8. ENDPOINTS (API) ---

@app.get("/")
def leer_root(): return {"mensaje": "¡Bienvenido a la API de Chocomanía!"}


# --- ENDPOINTS DE USUARIO Y AUTENTICACIÓN ---

@app.post("/usuarios/registrar", response_model=UsuarioSchema, status_code=201)
def registrar_usuario(usuario_input: UsuarioCreate, db: Session = Depends(get_db)):
    if get_usuario_by_email(db, usuario_input.email):
        raise HTTPException(status_code=400, detail="El Email esta en uso")

    hashed_password = hashear_contraseña(usuario_input.contraseña)
    
    rol_asignado = Roles.cliente
    user_count = db.query(UsuarioDB).count()
    if user_count == 0:
        rol_asignado = Roles.administrador
        print(f"¡TESTING!: Usuario {usuario_input.email} creado como ADMINISTRADOR.")

    nuevo_usuario_db = UsuarioDB(
        email=usuario_input.email,
        hashed_password=hashed_password,
        rol=rol_asignado
    )
    db.add(nuevo_usuario_db)
    db.commit()
    db.refresh(nuevo_usuario_db)
    return nuevo_usuario_db

@app.post("/token", response_model=dict)
def login_para_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db)
):
    usuario = autenticar_usuario(db, form_data.username, form_data.password)
    if not usuario:
        raise HTTPException(status_code=401, detail="Email o contraseña incorrecta", headers={"WWW-Authenticate": "Bearer"})
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = crear_access_token(data={"sub": usuario.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/usuarios/me", response_model=UsuarioSchema)
async def leer_mi_perfil(current_user: UsuarioDB = Depends(get_current_user)):
    return current_user

@app.put("/usuarios/me/password")
def cambiar_contraseña(
    input: CambioContraseñaInput,
    current_user: UsuarioDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not verificar_contraseña(input.contraseña_actual, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="La contraseña actual es incorrecta")
    
    current_user.hashed_password = hashear_contraseña(input.nueva_contraseña)
    db.commit()
    return {"mensaje": "Contraseña actualizada exitosamente"}

@app.put("/admin/usuarios/{usuario_id}/rol", response_model=UsuarioSchema)
def asignar_rol(
    usuario_id: int, 
    rol_input: RolUpdate,
    admin_user: UsuarioDB = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    usuario = get_usuario_by_id(db, usuario_id)
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    usuario.rol = rol_input.nuevo_rol
    db.commit()
    db.refresh(usuario)
    return usuario

@app.put("/usuarios/me/datos", response_model=UsuarioSchema)
def actualizar_datos_personales(
    datos: DatosPersonalesUpdate,
    current_user: UsuarioDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_user.nombre = datos.nombre
    current_user.direccion = datos.direccion
    current_user.comuna = datos.comuna
    current_user.telefono = datos.telefono
    db.commit()
    db.refresh(current_user)
    return current_user

@app.put("/usuarios/me/suscripcion", response_model=UsuarioSchema)
def gestionar_suscripcion(
    suscripcion: SuscripcionInput,
    current_user: UsuarioDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_user.recibirPromos = suscripcion.recibirPromos
    db.commit()
    db.refresh(current_user)
    return current_user

# --- ENDPOINTS DE CATÁLOGO (Productos) ---

@app.post("/productos/", response_model=ProductoSchema, status_code=201)
def crear_producto(
    producto_input: ProductoCreate,
    admin_user: UsuarioDB = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    nuevo_producto_db = ProductoDB(
        **producto_input.model_dump(),
        activo=True
    )
    db.add(nuevo_producto_db)
    db.commit()
    db.refresh(nuevo_producto_db)
    return nuevo_producto_db

@app.get("/productos/", response_model=List[ProductoSchema])
def leer_productos(tipo: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(ProductoDB).filter(ProductoDB.activo == True)
    
    if tipo:
        query = query.filter(ProductoDB.tipo.ilike(f"%{tipo}%")) 
        
    return query.all()

@app.put("/productos/{producto_id}", response_model=ProductoSchema)
def actualizar_producto(
    producto_id: int, 
    producto_update: ProductoUpdate,
    admin_user: UsuarioDB = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    producto = get_producto_by_id(db, producto_id)
    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado")
        
    update_data = producto_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(producto, key, value)
    
    db.commit()
    db.refresh(producto)
    return producto

# --- ENDPOINTS DE PAGO Y PEDIDOS ---

@app.post("/pedidos/crear-pago", response_model=dict)
def crear_pedido_y_pago(
    pedido_input: PedidoCreateInput,
    current_user: UsuarioDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    total_calculado = 0.0
    
    for item in pedido_input.items:
        producto = get_producto_by_id(db, item.producto_id)
        if not producto or not producto.activo or producto.stock < item.cantidad:
             raise HTTPException(status_code=400, detail=f"Problema con producto ID {item.producto_id}")
        
        total_calculado += producto.precio * item.cantidad
        
    nuevo_pedido_db = PedidoDB(
        usuario_id=current_user.id,
        total=total_calculado,
        estado=EstadoPedido.pendiente_de_pago
        # ¡CORREGIDO! Se borró la línea 'seguimiento_id=...'
    )
    db.add(nuevo_pedido_db)
    db.commit()
    db.refresh(nuevo_pedido_db)
    
    # (Faltaría la lógica de la tabla 'pedido_items_tabla' para asociar productos)
    
    return {"redirect_url": f"https://simulador-webpay.cl/pay?token={nuevo_pedido_db.id}"}

@app.post("/pedidos/{pedido_id}/solicitar-factura", response_model=dict)
def solicitar_factura(
    pedido_id: int,
    factura_input: FacturaInput,
    current_user: UsuarioDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    pedido = get_pedido_by_id(db, pedido_id)
    if not pedido or pedido.usuario_id != current_user.id:
        raise HTTPException(status_code=404, detail="Pedido no encontrado")
    if pedido.estado != EstadoPedido.pendiente_de_pago:
        raise HTTPException(status_code=400, detail="Solo se puede solicitar factura antes del pago")

    print(f"Pedido {pedido_id} marcado para Factura con RUT {factura_input.rut}")
    # (En una app real, guardarías 'factura_input' en el pedido para usarlo post-pago)
    return {"mensaje": "Datos de facturación recibidos. Se generará al aprobar el pago."}

@app.get("/pagos/confirmacion", response_model=dict)
def confirmar_pago_simulado(token: int, simul_status: str, db: Session = Depends(get_db)):
    pedido = get_pedido_by_id(db, token)
    if not pedido or pedido.estado != EstadoPedido.pendiente_de_pago:
        raise HTTPException(status_code=404, detail="Pedido no válido o ya procesado")

    if simul_status == "aprobado":
        pedido.estado = EstadoPedido.en_preparacion 
        print(f"Pedido {pedido.id} ahora en preparación.")
        
        nuevo_doc = DocumentoDB(
            pedido_id=pedido.id,
            tipo=TipoDocumento.boleta, 
            total=pedido.total
        )
        db.add(nuevo_doc)
        
        nuevo_seguimiento = SeguimientoDB(
            pedido_id=pedido.id,
            estado=EstadoSeguimiento.en_camino,
            hora_estimada_llegada= (datetime.now(timezone.utc) + timedelta(hours=1)).time().isoformat()
        )
        db.add(nuevo_seguimiento)
        
        enviar_notificacion_interna(
             db,
             EnviarNotificacionInput(pedido_id=pedido.id, tipo=TipoNotificacion.pedido_despachado)
        )
        
        db.commit()
        return {"mensaje": "Pago aprobado."}
    else:
        pedido.estado = EstadoPedido.rechazado
        db.commit()
        return {"mensaje": "Transacción no autorizada"}

@app.put("/pedidos/{pedido_id}/cancelar", response_model=PedidoSchema)
def cancelar_pedido(
    pedido_id: int,
    current_user: UsuarioDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    pedido = get_pedido_by_id(db, pedido_id)
    if not pedido or pedido.usuario_id != current_user.id:
        raise HTTPException(status_code=404, detail="Pedido no encontrado")
    if pedido.estado in [EstadoPedido.despachado, EstadoPedido.entregado]:
        raise HTTPException(status_code=400, detail="No se puede cancelar, el pedido ya fue despachado")
        
    pedido.estado = EstadoPedido.cancelado
    db.commit()
    print(f"Pedido {pedido.id} marcado como CANCELADO.")
    return pedido


# --- ENDPOINTS DE REPORTES (CORREGIDO CON 'func.date') ---

@app.get("/reportes/ventas")
def generar_reporte_ventas(
    fecha_inicio: date, 
    fecha_fin: date,
    formato: str = "json",
    admin_user: UsuarioDB = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    estados_de_venta = [
        EstadoPedido.pagado, 
        EstadoPedido.en_preparacion, 
        EstadoPedido.despachado, 
        EstadoPedido.entregado
    ]
    
    # ¡CORRECCIÓN DE ZONA HORARIA!
    # Comparamos la PARTE DE FECHA de la BBDD (UTC) con las fechas de entrada
    pedidos_pagados = db.query(PedidoDB).filter(
        PedidoDB.estado.in_(estados_de_venta),
        func.date(PedidoDB.fecha_creacion) >= fecha_inicio,
        func.date(PedidoDB.fecha_creacion) <= fecha_fin
    ).all()

    if not pedidos_pagados:
        return {"mensaje": "Sin datos disponibles para este período"}

    total_ventas = sum(p.total for p in pedidos_pagados)
    detalle_pedidos = [
        {"id": p.id, "fecha": p.fecha_creacion.isoformat(), "total": p.total} 
        for p in pedidos_pagados
    ]
    reporte_data = {
        "periodo": f"{fecha_inicio.isoformat()} al {fecha_fin.isoformat()}",
        "total_ventas": total_ventas,
        "cantidad_pedidos": len(pedidos_pagados),
        "detalle": detalle_pedidos
    }

    if formato == "json":
        return reporte_data
    elif formato == "excel" or formato == "pdf":
        output = io.StringIO()
        output.write("id,fecha,total\n")
        for p in detalle_pedidos: output.write(f"{p['id']},{p['fecha']},{p['total']}\n")
        file_content = output.getvalue()
        output.close()
        return StreamingResponse(
            io.BytesIO(file_content.encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=reporte_{fecha_inicio}_a_{fecha_fin}.csv"}
        )
    return HTTPException(status_code=400, detail="Formato no soportado")

# --- ENDPOINTS DE DASHBOARD (CORREGIDO CON 'func.date') ---

@app.get("/dashboard/ventas", response_model=DashboardVentas)
def get_dashboard_ventas(
    fecha: date,
    admin_user: UsuarioDB = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    estados_de_venta = [EstadoPedido.pagado, EstadoPedido.en_preparacion, EstadoPedido.despachado, EstadoPedido.entregado]
    
    # ¡CORRECCIÓN DE ZONA HORARIA!
    pedidos_del_dia = db.query(PedidoDB).filter(
        PedidoDB.estado.in_(estados_de_venta),
        func.date(PedidoDB.fecha_creacion) == fecha
    ).all()
    
    if not pedidos_del_dia:
        raise HTTPException(status_code=404, detail="No hay ventas para la fecha seleccionada")

    total_acumulado = sum(p.total for p in pedidos_del_dia)
    ticket_promedio = total_acumulado / len(pedidos_del_dia)
    
    top_productos_simulado = ["Bombones Finos (BBDD)", "Tableta Amarga (BBDD)"]
    ventas_por_hora_simulado = [VentasPorHora(hora=h, total=round(random.uniform(5000, 20000), 0)) for h in range(9, 18)]
    
    return DashboardVentas(
        total_acumulado=total_acumulado,
        ticket_promedio=ticket_promedio,
        top_productos=top_productos_simulado,
        ventas_por_hora=ventas_por_hora_simulado
    )

@app.get("/dashboard/pedidos-en-curso", response_model=List[DashboardPedidoActivo])
def get_dashboard_pedidos_activos(
    fecha: date,
    admin_user: UsuarioDB = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    estados_activos = [EstadoPedido.en_preparacion, EstadoPedido.despachado]

    # ¡CORRECCIÓN DE ZONA HORARIA!
    pedidos_activos = db.query(PedidoDB).filter(
        PedidoDB.estado.in_(estados_activos),
        func.date(PedidoDB.fecha_creacion) == fecha
    ).all()
    
    dashboard_list = []
    for p in pedidos_activos:
        cliente = get_usuario_by_id(db, p.usuario_id)
        dashboard_list.append(DashboardPedidoActivo(
            id=f"P-{p.id}",
            cliente=cliente.nombre if cliente else "N/A",
            estado=p.estado.value,
            tiempo_estimado=f"{random.randint(5, 20)} min",
            encargado="Laura Pérez (Simulado)"
        ))
    return dashboard_list


# --- ENDPOINTS DE NOTIFICACIONES ---

def enviar_notificacion_interna(db: Session, notificacion_input: EnviarNotificacionInput):
    pedido = get_pedido_by_id(db, notificacion_input.pedido_id)
    if not pedido: return 
    
    mensaje = f"Tu pedido {pedido.id} "
    hora_estimada_str = None
    if notificacion_input.tipo == TipoNotificacion.pedido_despachado:
        seguimiento = get_seguimiento_by_pedido_id(db, pedido.id)
        if seguimiento and seguimiento.hora_estimada_llegada:
             hora_estimada_str = seguimiento.hora_estimada_llegada
             mensaje += f"ha sido despachado. Llegada estimada: {hora_estimada_str}."
        else:
             mensaje += "ha sido despachado."
    elif notificacion_input.tipo == TipoNotificacion.retraso_entrega:
        mensaje += f"sufrirá un retraso. {notificacion_input.mensaje_opcional or ''}"

    nueva_notificacion_db = NotificacionDB(
        pedido_id=pedido.id,
        tipo=notificacion_input.tipo,
        mensaje=mensaje,
        hora_estimada=hora_estimada_str
    )
    db.add(nueva_notificacion_db)
    print(f"NOTIFICACION (Simulada) para Pedido {pedido.id}: {mensaje}")
    return nueva_notificacion_db

@app.post("/notificaciones/enviar", response_model=NotificacionSchema, status_code=201)
def enviar_notificacion_endpoint(
    notificacion_input: EnviarNotificacionInput,
    db: Session = Depends(get_db)
):
    notificacion = enviar_notificacion_interna(db, notificacion_input)
    if not notificacion:
         raise HTTPException(status_code=404, detail="Pedido no encontrado para notificar")
    db.commit() # Commit aquí
    db.refresh(notificacion)
    return notificacion

@app.put("/notificaciones/pedido/{pedido_id}/actualizar", response_model=NotificacionSchema)
def actualizar_notificacion_endpoint(
    pedido_id: int,
    update_input: ActualizarNotificacionInput,
    db: Session = Depends(get_db)
):
    notificaciones_pedido = get_notificacion_by_pedido_id(db, pedido_id)
    if not notificaciones_pedido:
        raise HTTPException(status_code=404, detail="No hay notificaciones para este pedido")
    
    ultima_notificacion = notificaciones_pedido[-1]
    ultima_notificacion.mensaje = update_input.mensaje_nuevo
    if update_input.nueva_hora_estimada:
        ultima_notificacion.hora_estimada = update_input.nueva_hora_estimada.isoformat()
    
    db.commit()
    db.refresh(ultima_notificacion)
    print(f"NOTIFICACION ACTUALIZADA (Simulada) Pedido {pedido_id}: {ultima_notificacion.mensaje}")
    return ultima_notificacion


# --- ENDPOINTS DE SEGUIMIENTO ---

@app.get("/seguimiento/{pedido_id}", response_model=SeguimientoSchema)
def obtener_seguimiento_cliente(
    pedido_id: int, 
    current_user: UsuarioDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    pedido = get_pedido_by_id(db, pedido_id)
    if not pedido or pedido.usuario_id != current_user.id:
        raise HTTPException(status_code=404, detail="Pedido no encontrado o no autorizado")

    seguimiento = get_seguimiento_by_pedido_id(db, pedido.id)
    if not seguimiento:
         raise HTTPException(status_code=404, detail="Seguimiento no iniciado para este pedido")

    if seguimiento.estado == EstadoSeguimiento.en_camino:
        seguimiento.lat = round(random.uniform(-33.4, -33.5), 6)
        seguimiento.lng = round(random.uniform(-70.6, -70.7), 6)
        db.commit()
        db.refresh(seguimiento)
    
    return seguimiento

@app.put("/seguimiento/{pedido_id}/entregar", response_model=SeguimientoSchema)
def confirmar_entrega_repartidor(
    pedido_id: int,
    entrega_input: ConfirmarEntregaInput,
    repartidor: UsuarioDB = Depends(get_current_repartidor_user),
    db: Session = Depends(get_db)
):
    seguimiento = get_seguimiento_by_pedido_id(db, pedido_id)
    if not seguimiento:
        raise HTTPException(status_code=404, detail="Seguimiento no encontrado")
    if seguimiento.estado == EstadoSeguimiento.entregado:
        raise HTTPException(status_code=400, detail="El pedido ya fue marcado como entregado")

    seguimiento.estado = EstadoSeguimiento.entregado
    seguimiento.lat = None
    seguimiento.lng = None

    pedido = get_pedido_by_id(db, pedido_id)
    if pedido:
        pedido.estado = EstadoPedido.entregado
        print(f"Pedido {pedido_id} marcado como Entregado por Repartidor {repartidor.email}.")

    db.commit()
    db.refresh(seguimiento)
    return seguimiento