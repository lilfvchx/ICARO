import asyncdispatch, asyncnet, net, strutils, sequtils, tables, times, json, random
import std/[sha1, strformat, logging]

# Tipos de error personalizados
type
  P2PError* = object of CatchableError

# Configuración del nodo P2P
type
  P2PConfig* = object
    nodeId*: string                # ID único del nodo
    maxPeers*: int                 # Número máximo de peers
    refreshInterval*: float        # Intervalo de actualización (segundos)
    bucketSize*: int               # Tamaño de buckets Kademlia
    protocolVersion*: string       # Versión del protocolo
    enableFallback*: bool          # Habilitar modos de fallback
    fallbackEndpoints*: seq[string]  # Endpoints para fallback
    maxRetries*: int               # Máximo de reintentos
    retryDelay*: float             # Retraso entre reintentos (segundos)
    reputationThreshold*: float    # Umbral de reputación para peers
    encryptionLevel*: int          # Nivel de cifrado (0-3)
    enableDHT*: bool               # Habilitar DHT
    enableRelay*: bool             # Habilitar relay de mensajes
    enableDiscovery*: bool         # Habilitar descubrimiento automático

# Información de peer
type
  PeerInfo* = object
    nodeId*: string
    address*: string
    port*: int
    lastSeen*: int64
    reputation*: float
    isBootstrap*: bool
    connectionType*: string

# Bucket Kademlia
type
  KBucket* = object
    peers*: seq[PeerInfo]
    lastUpdated*: int64

# Nodo DHT
type
  DHTNode* = object
    nodeId*: string
    buckets*: array[160, KBucket]  # 160 bits para SHA-1
    config*: P2PConfig

# Nodo P2P principal
type
  P2PNode* = object
    config*: P2PConfig
    dht*: DHTNode
    peers*: Table[string, PeerInfo]
    server*: AsyncSocket
    fallbackSockets*: seq[AsyncSocket]
    isRunning*: bool
    messageHandlers*: Table[string, proc(data: string): Future[void] {.async.}]

# Utilidades para cálculo de distancia Kademlia
proc xorDistance(a, b: string): string =
  ## Calcula la distancia XOR entre dos IDs de nodo
  result = ""
  for i in 0..<min(a.len, b.len):
    result.add(char(ord(a[i]) xor ord(b[i])))

proc getBucketIndex(nodeId, targetId: string): int =
  ## Obtiene el índice del bucket para un ID objetivo
  let distance = xorDistance(nodeId, targetId)
  for i, c in distance:
    if c != '\0':
      return i * 8 + countLeadingZeroBits(uint8(c))
  return 159

proc generateNodeId(): string =
  ## Genera un ID único para el nodo
  let timestamp = getTime().toUnix()
  let randomData = $rand(1000000)
  return $secureHash(fmt"{timestamp}_{randomData}")

# Implementación de configuración por defecto
proc defaultP2PConfig*(): P2PConfig =
  ## Crea una configuración por defecto
  result = P2PConfig(
    nodeId: generateNodeId(),
    maxPeers: 50,
    refreshInterval: 60.0,
    bucketSize: 20,
    protocolVersion: "1.0",
    enableFallback: true,
    fallbackEndpoints: @[],
    maxRetries: 3,
    retryDelay: 2.0,
    reputationThreshold: 0.5,
    encryptionLevel: 2,
    enableDHT: true,
    enableRelay: true,
    enableDiscovery: true
  )

# Inicialización del DHT
proc initDHT(config: P2PConfig): DHTNode =
  result = DHTNode(
    nodeId: config.nodeId,
    config: config
  )
  # Inicializar buckets vacíos
  for i in 0..<160:
    result.buckets[i] = KBucket(
      peers: @[],
      lastUpdated: getTime().toUnix()
    )

# Validación de configuración
proc validateConfig(config: P2PConfig): bool =
  ## Valida que la configuración sea correcta
  if config.nodeId.len == 0:
    return false
  if config.maxPeers <= 0:
    return false
  if config.bucketSize <= 0:
    return false
  if config.encryptionLevel < 0 or config.encryptionLevel > 3:
    return false
  return true

# Conexión a nodos bootstrap
proc connectToBootstrapNodes(node: var P2PNode, bootstrapNodes: seq[string]): Future[bool] {.async.} =
  ## Conecta a los nodos semilla para unirse a la red
  var connected = false
  
  for bootstrapAddr in bootstrapNodes:
    try:
      let parts = bootstrapAddr.split(":")
      if parts.len != 2:
        continue
        
      let host = parts[0]
      let port = parseInt(parts[1])
      
      var client = newAsyncSocket()
      await client.connect(host, Port(port))
      
      # Enviar mensaje de handshake
      let handshake = %*{
        "type": "handshake",
        "nodeId": node.config.nodeId,
        "version": node.config.protocolVersion,
        "timestamp": getTime().toUnix()
      }
      
      await client.send($handshake & "\n")
      
      # Recibir respuesta
      let response = await client.recvLine()
      let responseJson = parseJson(response)
      
      if responseJson["status"].getStr() == "ok":
        # Agregar peer a la DHT
        let peerInfo = PeerInfo(
          nodeId: responseJson["nodeId"].getStr(),
          address: host,
          port: port,
          lastSeen: getTime().toUnix(),
          reputation: 1.0,
          isBootstrap: true,
          connectionType: "TCP"
        )
        
        node.peers[peerInfo.nodeId] = peerInfo
        connected = true
        echo fmt"Conectado a bootstrap node: {bootstrapAddr}"
      
      client.close()
      
    except:
      echo fmt"Error conectando a {bootstrapAddr}: {getCurrentExceptionMsg()}"
      continue
  
  return connected

# Configuración de fallback
proc setupFallbackMechanisms(node: var P2PNode): Future[void] {.async.} =
  ## Configura los mecanismos de fallback
  if not node.config.enableFallback:
    return
    
  for endpoint in node.config.fallbackEndpoints:
    try:
      var fallbackSocket = newAsyncSocket()
      # Configurar conexión de fallback específica según el tipo
      if endpoint.startsWith("http://") or endpoint.startsWith("https://"):
        # HTTP Fallback - implementar cliente HTTP
        echo fmt"Configurando HTTP fallback: {endpoint}"
      elif endpoint.startsWith("ws://") or endpoint.startsWith("wss://"):
        # WebSocket Fallback
        echo fmt"Configurando WebSocket fallback: {endpoint}"
      
      node.fallbackSockets.add(fallbackSocket)
    except:
      echo fmt"Error configurando fallback {endpoint}: {getCurrentExceptionMsg()}"

# Manejo de mensajes entrantes
proc handleIncomingMessage(node: var P2PNode, client: AsyncSocket): Future[void] {.async.} =
  ## Maneja mensajes entrantes de peers
  try:
    while true:
      let message = await client.recvLine()
      if message.len == 0:
        break
        
      let msgJson = parseJson(message)
      let msgType = msgJson["type"].getStr()
      
      case msgType:
        of "handshake":
          # Responder handshake
          let response = %*{
            "status": "ok",
            "nodeId": node.config.nodeId,
            "version": node.config.protocolVersion,
            "timestamp": getTime().toUnix()
          }
          await client.send($response & "\n")
          
        of "ping":
          # Responder ping
          let pong = %*{
            "type": "pong",
            "nodeId": node.config.nodeId,
            "timestamp": getTime().toUnix()
          }
          await client.send($pong & "\n")
          
        of "find_node":
          # Buscar nodos cercanos en la DHT
          let targetId = msgJson["target"].getStr()
          let closestPeers = node.peers.values.toSeq()
          
          let response = %*{
            "type": "nodes_found",
            "nodes": closestPeers[0..min(19, closestPeers.len-1)]
          }
          await client.send($response & "\n")
          
        else:
          # Mensaje personalizado
          if node.messageHandlers.hasKey(msgType):
            await node.messageHandlers[msgType](message)
            
  except:
    echo fmt"Error manejando mensaje: {getCurrentExceptionMsg()}"
  finally:
    client.close()

# Servidor P2P
proc startP2PServer(node: var P2PNode): Future[void] {.async.} =
  ## Inicia el servidor P2P para recibir conexiones
  node.server = newAsyncSocket()
  node.server.setSockOpt(OptReuseAddr, true)
  
  let port = if node.config.fallbackEndpoints.len > 0:
    # Extraer puerto del primer endpoint
    let parts = node.config.fallbackEndpoints[0].split(":")
    if parts.len >= 3: parseInt(parts[2]) else: 8888
  else:
    8888
    
  node.server.bindAddr(Port(port))
  node.server.listen()
  
  echo fmt"Servidor P2P escuchando en puerto {port}"
  
  while node.isRunning:
    try:
      let client = await node.server.accept()
      asyncCheck node.handleIncomingMessage(client)
    except:
      if node.isRunning:
        echo fmt"Error en servidor P2P: {getCurrentExceptionMsg()}"

# Mantenimiento de la DHT
proc maintainDHT(node: var P2PNode): Future[void] {.async.} =
  ## Mantiene la DHT actualizada
  while node.isRunning:
    try:
      # Refrescar buckets antiguos
      let currentTime = getTime().toUnix()
      
      for i, bucket in node.dht.buckets:
        if currentTime - bucket.lastUpdated > node.config.refreshInterval.int64:
          # Buscar nodos aleatorios en este rango
          echo fmt"Refrescando bucket {i}"
          node.dht.buckets[i].lastUpdated = currentTime
      
      await sleepAsync(int(node.config.refreshInterval * 1000))
      
    except:
      echo fmt"Error manteniendo DHT: {getCurrentExceptionMsg()}"

# Función principal de inicialización
proc initializeP2PNode*(bootstrapNodes: seq[string], config: P2PConfig): Future[P2PNode] {.async, raises: [P2PError].} =
  ## Inicializa y arranca un nodo Kademlia para unirse a la red P2P con configuración avanzada
  try:
    # Validar configuración
    if not validateConfig(config):
      raise newException(P2PError, "Configuración inválida")
    
    # Crear nodo
    var node = P2PNode(
      config: config,
      dht: initDHT(config),
      peers: initTable[string, PeerInfo](),
      isRunning: true,
      messageHandlers: initTable[string, proc(data: string): Future[void] {.async.}]()
    )
    
    echo fmt"Inicializando nodo P2P con ID: {config.nodeId}"
    
    # Conectar a nodos bootstrap
    if bootstrapNodes.len > 0:
      let connected = await node.connectToBootstrapNodes(bootstrapNodes)
      if not connected:
        raise newException(P2PError, "No se pudo conectar a ningún nodo semilla")
    
    # Configurar mecanismos de fallback
    await node.setupFallbackMechanisms()
    
    # Iniciar servidor
    asyncCheck node.startP2PServer()
    
    # Iniciar mantenimiento de DHT
    if config.enableDHT:
      asyncCheck node.maintainDHT()
    
    echo "Nodo P2P inicializado exitosamente"
    return node
    
  except P2PError:
    raise
  except:
    raise newException(P2PError, fmt"Error inicializando nodo P2P: {getCurrentExceptionMsg()}")

# Funciones auxiliares para el nodo
proc addMessageHandler*(node: var P2PNode, msgType: string, handler: proc(data: string): Future[void] {.async.}) =
  ## Agrega un manejador personalizado para tipos de mensaje
  node.messageHandlers[msgType] = handler

proc stopP2PNode*(node: var P2PNode): Future[void] {.async.} =
  ## Detiene el nodo P2P
  node.isRunning = false
  if node.server != nil:
    node.server.close()
  for socket in node.fallbackSockets:
    socket.close()
  echo "Nodo P2P detenido"

proc getPeerCount*(node: P2PNode): int =
  ## Obtiene el número de peers conectados
  return node.peers.len

proc findNode*(node: P2PNode, targetId: string): seq[PeerInfo] =
  ## Busca los nodos más cercanos a un ID objetivo
  var peers = node.peers.values.toSeq()
  # Ordenar por distancia XOR (simplificado)
  peers.sort do (a, b: PeerInfo) -> int:
    let distA = xorDistance(node.config.nodeId, a.nodeId)
    let distB = xorDistance(node.config.nodeId, b.nodeId)
    cmp(distA, distB)
  
  return peers[0..min(19, peers.len-1)]
