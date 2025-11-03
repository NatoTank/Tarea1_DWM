from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse 
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timedelta, timezone, date, time
from enum import Enum
import io 
import random # Para simular ubicación

# --- LIBRERÍAS DE SEGURIDAD ---
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- 1. MODELOS DE DATOS ---

# (Usuario)
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

class Roles(str, Enum):
    cliente = "cliente"
    administrador = "administrador"
    cocinero = "cocinero"
    repartidor = "repartidor"

class RolUpdate(BaseModel):
    nuevo_rol: Roles

class Usuario(BaseModel):
    id: int
    email: str
    hashed_password: str
    rol: Roles = Roles.cliente
    nombre: Optional[str] = None
    direccion: Optional[str] = None
    comuna: Optional[str] = None
    telefono: Optional[str] = None
    recibirPromos: bool = True

class TokenData(BaseModel):
    email: Optional[str] = None

# (Producto)
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

class Producto(ProductoBase):
    id: int
    activo: bool = True

# (Pedido)
class EstadoPedido(str, Enum):
    pendiente_de_pago = "pendiente_de_pago"
    pagado = "pagado"
    en_preparacion = "en_preparacion"
    despachado = "despachado"
    entregado = "entregado" 
    rechazado = "rechazado"
    cancelado = "cancelado"

class PedidoItemInput(BaseModel):
    producto_id: int
    cantidad: int

class PedidoCreateInput(BaseModel):
    items: List[PedidoItemInput]

class PedidoItem(BaseModel):
    producto_id: int
    cantidad: int
    precio_en_el_momento: float

class Pedido(BaseModel):
    id: int
    usuario_id: int
    items: List[PedidoItem]
    total: float
    estado: EstadoPedido = EstadoPedido.pendiente_de_pago
    fecha_creacion: datetime
    seguimiento_id: Optional[str] = None

# (Notificaciones)
class TipoNotificacion(str, Enum):
    pedido_recibido = "pedido_recibido"
    pedido_despachado = "pedido_despachado"
    retraso_entrega = "retraso_entrega"

class EnviarNotificacionInput(BaseModel):
    pedido_id: int
    tipo: TipoNotificacion
    mensaje_opcional: Optional[str] = None

class ActualizarNotificacionInput(BaseModel):
    mensaje_nuevo: str
    nueva_hora_estimada: Optional[time] = None

class Notificacion(BaseModel):
    id: int
    pedido_id: int
    tipo: TipoNotificacion
    mensaje: str
    hora_estimada: Optional[time] = None
    fecha_envio: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# (Seguimiento)
class EstadoSeguimiento(str, Enum):
    en_camino = "En Camino"
    entregado = "Entregado"
    problema_reportado = "Problema Reportado"

class Ubicacion(BaseModel):
    lat: float
    lng: float

class ConfirmarEntregaInput(BaseModel):
    confirmacion_texto: str = "Entregado OK" 

class ActualizarUbicacionInput(BaseModel):
     lat: float
     lng: float

class ReportarProblemaInput(BaseModel):
    descripcion: str

class Seguimiento(BaseModel):
    pedido_id: int 
    estado: EstadoSeguimiento = EstadoSeguimiento.en_camino
    hora_estimada_llegada: Optional[time] = None
    repartidor_asignado: Optional[str] = None
    ubicacion_actual: Optional[Ubicacion] = None
    historial_ubicaciones: List[Ubicacion] = []


# --- 2. CONFIGURACIÓN DE SEGURIDAD ---
SECRET_KEY = "tu-clave-secreta-super-dificil-de-adivinar"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# --- 3. FUNCIONES HELPER DE SEGURIDAD ---
def verificar_contraseña(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def hashear_contraseña(password: str) -> str:
    return pwd_context.hash(password)

def crear_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- 4. "BASE DE DATOS" (temporal) ---
db_usuarios: List[Usuario] = []
db_productos: List[Producto] = []
db_pedidos: List[Pedido] = []
db_notificaciones: List[Notificacion] = []
db_seguimientos: List[Seguimiento] = []
usuario_id_counter = 0
producto_id_counter = 0
pedido_id_counter = 0
notificacion_id_counter = 0


# --- 5. FUNCIONES DE AUTENTICACIÓN Y BBDD ---
def get_usuario_by_email(email: str) -> Optional[Usuario]:
    for user in db_usuarios:
        if user.email == email: return user
    return None

def get_usuario_by_id(user_id: int) -> Optional[Usuario]:
    for user in db_usuarios:
        if user.id == user_id: return user
    return None

def get_producto_by_id(producto_id: int) -> Optional[Producto]:
    for p in db_productos:
        if p.id == producto_id: return p
    return None

def get_pedido_by_id(pedido_id: int) -> Optional[Pedido]:
    for p in db_pedidos:
        if p.id == pedido_id: return p
    return None

def get_notificacion_by_pedido_id(pedido_id: int) -> List[Notificacion]:
    return [n for n in db_notificaciones if n.pedido_id == pedido_id]

def get_seguimiento_by_pedido_id(pedido_id: int) -> Optional[Seguimiento]:
    for s in db_seguimientos:
        if s.pedido_id == pedido_id:
            return s
    return None

def autenticar_usuario(email: str, contraseña: str) -> Optional[Usuario]:
    usuario = get_usuario_by_email(email)
    if not usuario or not verificar_contraseña(contraseña, usuario.hashed_password):
        return None
    return usuario

async def get_current_user(token: str = Depends(oauth2_scheme)) -> Usuario:
    credentials_exception = HTTPException(status_code=401, detail="Credenciales inválidas")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
    except JWTError:
        raise credentials_exception
    usuario = get_usuario_by_email(email)
    if usuario is None: raise credentials_exception
    return usuario

async def get_current_admin_user(current_user: Usuario = Depends(get_current_user)) -> Usuario:
    if current_user.rol != Roles.administrador:
        raise HTTPException(status_code=403, detail="Requiere permisos de administrador")
    return current_user

async def get_current_repartidor_user(current_user: Usuario = Depends(get_current_user)) -> Usuario:
    if current_user.rol != Roles.repartidor:
        raise HTTPException(status_code=403, detail="Acción solo para repartidores")
    return current_user


# --- 6. CREA LA APP ---
app = FastAPI(
    title="Chocomanía API",
    description="API para el sistema de E-commerce Chocomanía"
)

# --- 7. ENDPOINTS (API) ---

@app.get("/")
def leer_root(): return {"mensaje": "¡Bienvenido a la API de Chocomanía!"}


# --- ENDPOINTS DE USUARIO Y AUTENTICACIÓN ---

@app.post("/usuarios/registrar", response_model=Usuario, status_code=201)
def registrar_usuario(usuario_input: UsuarioCreate):
    global usuario_id_counter
    
    if get_usuario_by_email(usuario_input.email):
        raise HTTPException(status_code=400, detail="El Email esta en uso")

    usuario_id_counter += 1
    hashed_password = hashear_contraseña(usuario_input.contraseña)
    
    rol_asignado = Roles.cliente
    if usuario_id_counter == 1:
        rol_asignado = Roles.administrador
        print(f"¡TESTING!: Usuario {usuario_input.email} creado como ADMINISTRADOR.")

    nuevo_usuario = Usuario(
        id=usuario_id_counter,
        email=usuario_input.email,
        hashed_password=hashed_password,
        rol=rol_asignado
    )
    
    db_usuarios.append(nuevo_usuario)
    return nuevo_usuario

@app.post("/token")
def login_para_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    usuario = autenticar_usuario(form_data.username, form_data.password)
    if not usuario:
        raise HTTPException(
            status_code=401,
            detail="Email o contraseña incorrecta",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = crear_access_token(
        data={"sub": usuario.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/usuarios/me", response_model=Usuario)
async def leer_mi_perfil(current_user: Usuario = Depends(get_current_user)):
    return current_user

@app.put("/usuarios/me/password")
def cambiar_contraseña(
    input: CambioContraseñaInput,
    current_user: Usuario = Depends(get_current_user)
):
    if not verificar_contraseña(input.contraseña_actual, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="La contraseña actual es incorrecta")
    
    nuevo_hashed_password = hashear_contraseña(input.nueva_contraseña)
    
    for idx, user in enumerate(db_usuarios):
        if user.id == current_user.id:
            user.hashed_password = nuevo_hashed_password
            db_usuarios[idx] = user
            break
            
    return {"mensaje": "Contraseña actualizada exitosamente"}

@app.put("/admin/usuarios/{usuario_id}/rol", response_model=Usuario)
def asignar_rol(
    usuario_id: int, 
    rol_input: RolUpdate,
    admin_user: Usuario = Depends(get_current_admin_user)
):
    usuario = get_usuario_by_id(usuario_id)
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
    for idx, user in enumerate(db_usuarios):
        if user.id == usuario.id:
            user.rol = rol_input.nuevo_rol
            db_usuarios[idx] = user
            return user
            
    raise HTTPException(status_code=404, detail="Usuario no encontrado")

# --- Pega esto después de la función asignar_rol ---

@app.put("/usuarios/me/datos", response_model=Usuario)
def actualizar_datos_personales(
    datos: DatosPersonalesUpdate,
    current_user: Usuario = Depends(get_current_user)
):
    """
    Implementa la historia UX-B-02: Guardar Datos Personales.
    Permite al usuario logueado actualizar su propio nombre, dirección, etc.
    """
    
    # Buscamos al usuario en la BBDD (aunque current_user ya lo es, 
    # necesitamos el índice para actualizar la lista)
    for idx, usuario in enumerate(db_usuarios):
        if usuario.id == current_user.id:
            
            # Actualiza el objeto 'usuario' con los datos del DTO 'datos'
            usuario.nombre = datos.nombre
            usuario.direccion = datos.direccion
            usuario.comuna = datos.comuna
            usuario.telefono = datos.telefono
            
            db_usuarios[idx] = usuario # Guarda el usuario actualizado en la "BBDD"
            return usuario
    
    # Esto no debería pasar si el token es válido, pero por si acaso
    raise HTTPException(status_code=404, detail="Usuario no encontrado")

# --- FIN DE LOS ENDPOINTS DE USUARIO ---


# --- ENDPOINTS DE CATÁLOGO (Productos) ---

@app.post("/productos/", response_model=Producto, status_code=201)
def crear_producto(
    producto_input: ProductoCreate,
    admin_user: Usuario = Depends(get_current_admin_user)
):
    global producto_id_counter
    producto_id_counter += 1
    
    nuevo_producto = Producto(
        id=producto_id_counter,
        activo=True,
        **producto_input.model_dump()
    )
    
    db_productos.append(nuevo_producto)
    return nuevo_producto

@app.get("/productos/", response_model=List[Producto])
def leer_productos():
    productos_activos = [p for p in db_productos if p.activo]
    return productos_activos

@app.put("/productos/{producto_id}", response_model=Producto)
def actualizar_producto(
    producto_id: int, 
    producto_update: ProductoUpdate,
    admin_user: Usuario = Depends(get_current_admin_user)
):
    for idx, producto in enumerate(db_productos):
        if producto.id == producto_id:
            update_data = producto_update.model_dump(exclude_unset=True)
            for key, value in update_data.items():
                setattr(producto, key, value)
            db_productos[idx] = producto
            return producto

    raise HTTPException(status_code=404, detail="Producto no encontrado")


# --- ENDPOINTS DE PAGO Y PEDIDOS ---

@app.post("/pedidos/crear-pago", response_model=dict)
def crear_pedido_y_pago(
    pedido_input: PedidoCreateInput,
    current_user: Usuario = Depends(get_current_user)
):
    global pedido_id_counter
    items_del_pedido = []
    total_calculado = 0.0

    for item in pedido_input.items:
        producto = get_producto_by_id(item.producto_id)
        
        if not producto or not producto.activo or producto.stock < item.cantidad:
             raise HTTPException(status_code=400, detail=f"Problema con producto ID {item.producto_id}")
        
        precio_item = producto.precio
        items_del_pedido.append(PedidoItem(
            producto_id=item.producto_id, 
            cantidad=item.cantidad, 
            precio_en_el_momento=precio_item
        ))
        total_calculado += precio_item * item.cantidad

    pedido_id_counter += 1
    nuevo_pedido = Pedido(
        id=pedido_id_counter,
        usuario_id=current_user.id,
        items=items_del_pedido,
        total=total_calculado,
        estado=EstadoPedido.pendiente_de_pago,
        fecha_creacion=datetime.now(timezone.utc),
        seguimiento_id=str(pedido_id_counter)
    )
    db_pedidos.append(nuevo_pedido)
    
    return {"redirect_url": f"https://simulador-webpay.cl/pay?token={nuevo_pedido.id}"}


@app.get("/pagos/confirmacion", response_model=dict)
def confirmar_pago_simulado(token: int, simul_status: str):
    pedido = get_pedido_by_id(token)
    if not pedido or pedido.estado != EstadoPedido.pendiente_de_pago:
        raise HTTPException(status_code=404, detail="Pedido no válido o ya procesado")

    if simul_status == "aprobado":
        pedido.estado = EstadoPedido.pagado
        print(f"Pedido {pedido.id} Pagado. Estado actual: {pedido.estado}")
        
        pedido.estado = EstadoPedido.en_preparacion 
        print(f"Pedido {pedido.id} ahora en preparación.")
        
        nuevo_seguimiento = Seguimiento(
            pedido_id=pedido.id,
            estado=EstadoSeguimiento.en_camino,
            hora_estimada_llegada= (datetime.now(timezone.utc) + timedelta(hours=1)).time()
        )
        db_seguimientos.append(nuevo_seguimiento)
        print(f"Seguimiento creado para Pedido {pedido.id}.")

        enviar_notificacion_interna(
             EnviarNotificacionInput(pedido_id=pedido.id, tipo=TipoNotificacion.pedido_despachado)
        )

        return {"mensaje": "Pago aprobado."}
    else:
        pedido.estado = EstadoPedido.rechazado
        return {"mensaje": "Transacción no autorizada"}


# --- ENDPOINTS DE REPORTES (CORREGIDO) ---

@app.get("/reportes/ventas")
def generar_reporte_ventas(
    fecha_inicio: date, 
    fecha_fin: date,
    formato: str = "json",
    admin_user: Usuario = Depends(get_current_admin_user)
):
    
    # --- INICIO DE LA CORRECCIÓN ---
    # Definimos todos los estados que cuentan como una venta
    estados_de_venta = [
        EstadoPedido.pagado, 
        EstadoPedido.en_preparacion, 
        EstadoPedido.despachado, 
        EstadoPedido.entregado
    ]

    pedidos_pagados = [
        p for p in db_pedidos 
        if p.estado in estados_de_venta and  # <-- ¡AQUÍ ESTÁ EL CAMBIO!
           fecha_inicio <= p.fecha_creacion.date() <= fecha_fin
    ]
    # --- FIN DE LA CORRECIÓN ---

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
        for p in detalle_pedidos:
            output.write(f"{p['id']},{p['fecha']},{p['total']}\n")
        
        file_content = output.getvalue()
        output.close()
        
        return StreamingResponse(
            io.BytesIO(file_content.encode("utf-8")),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=reporte_{fecha_inicio}_a_{fecha_fin}.csv"
            }
        )

    return HTTPException(status_code=400, detail="Formato no soportado")


# --- ENDPOINTS DE NOTIFICACIONES ---

def enviar_notificacion_interna(notificacion_input: EnviarNotificacionInput):
    global notificacion_id_counter
    pedido = get_pedido_by_id(notificacion_input.pedido_id)
    if not pedido: return 
    
    mensaje = f"Tu pedido {pedido.id} "
    hora_estimada = None
    if notificacion_input.tipo == TipoNotificacion.pedido_despachado:
        seguimiento = get_seguimiento_by_pedido_id(pedido.id)
        if seguimiento and seguimiento.hora_estimada_llegada:
             hora_estimada = seguimiento.hora_estimada_llegada
             mensaje += f"ha sido despachado. Llegada estimada: {hora_estimada.strftime('%H:%M')}."
        else:
             mensaje += "ha sido despachado."
    elif notificacion_input.tipo == TipoNotificacion.retraso_entrega:
        mensaje += f"sufrirá un retraso. {notificacion_input.mensaje_opcional or ''}"

    notificacion_id_counter += 1
    nueva_notificacion = Notificacion(
        id=notificacion_id_counter,
        pedido_id=pedido.id,
        tipo=notificacion_input.tipo,
        mensaje=mensaje,
        hora_estimada=hora_estimada
    )
    db_notificaciones.append(nueva_notificacion)
    print(f"NOTIFICACION (Simulada) para Pedido {pedido.id}: {mensaje}")
    return nueva_notificacion

@app.post("/notificaciones/enviar", response_model=Notificacion, status_code=201)
def enviar_notificacion_endpoint(
    notificacion_input: EnviarNotificacionInput
    # admin_user: Usuario = Depends(get_current_admin_user) 
):
    notificacion = enviar_notificacion_interna(notificacion_input)
    if not notificacion:
         raise HTTPException(status_code=404, detail="Pedido no encontrado para notificar")
    return notificacion

@app.put("/notificaciones/pedido/{pedido_id}/actualizar", response_model=Notificacion)
def actualizar_notificacion_endpoint(
    pedido_id: int,
    update_input: ActualizarNotificacionInput
    # admin_user: Usuario = Depends(get_current_admin_user)
):
    notificaciones_pedido = get_notificacion_by_pedido_id(pedido_id)
    if not notificaciones_pedido:
        raise HTTPException(status_code=404, detail="No hay notificaciones para este pedido")
    
    ultima_notificacion = notificaciones_pedido[-1]
    ultima_notificacion.mensaje = update_input.mensaje_nuevo
    if update_input.nueva_hora_estimada:
        ultima_notificacion.hora_estimada = update_input.nueva_hora_estimada

    for i, n in enumerate(db_notificaciones):
        if n.id == ultima_notificacion.id:
            db_notificaciones[i] = ultima_notificacion
            break

    print(f"NOTIFICACION ACTUALIZADA (Simulada) Pedido {pedido_id}: {ultima_notificacion.mensaje}")
    return ultima_notificacion


# --- ENDPOINTS DE SEGUIMIENTO ---

@app.get("/seguimiento/{pedido_id}", response_model=Seguimiento)
def obtener_seguimiento_cliente(
    pedido_id: int, 
    current_user: Usuario = Depends(get_current_user)
):
    pedido = get_pedido_by_id(pedido_id)
    if not pedido or pedido.usuario_id != current_user.id:
        raise HTTPException(status_code=404, detail="Pedido no encontrado o no autorizado")

    seguimiento = get_seguimiento_by_pedido_id(pedido_id)
    if not seguimiento:
         raise HTTPException(status_code=404, detail="Seguimiento no iniciado para este pedido")

    if seguimiento.estado == EstadoSeguimiento.en_camino:
        seguimiento.ubicacion_actual = Ubicacion(lat=round(random.uniform(-33.4, -33.5), 6), lng=round(random.uniform(-70.6, -70.7), 6))
    
    return seguimiento

@app.put("/seguimiento/{pedido_id}/entregar", response_model=Seguimiento)
def confirmar_entrega_repartidor(
    pedido_id: int,
    entrega_input: ConfirmarEntregaInput,
    repartidor: Usuario = Depends(get_current_repartidor_user)
):
    seguimiento = get_seguimiento_by_pedido_id(pedido_id)
    if not seguimiento:
        raise HTTPException(status_code=404, detail="Seguimiento no encontrado")

    if seguimiento.estado == EstadoSeguimiento.entregado:
        raise HTTPException(status_code=400, detail="El pedido ya fue marcado como entregado")

    seguimiento.estado = EstadoSeguimiento.entregado
    seguimiento.ubicacion_actual = None

    pedido = get_pedido_by_id(pedido_id)
    if pedido:
        pedido.estado = EstadoPedido.entregado
        print(f"Pedido {pedido_id} marcado como Entregado por Repartidor {repartidor.email}.")

    return seguimiento