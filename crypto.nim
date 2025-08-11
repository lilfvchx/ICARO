import std/[random, os, times, strutils]
import nimcrypto/[sha2, hmac, utils]
import sodium
import chronicles

type
  CryptoError* = object of CatchableError
  
  KeyDerivationParams* = object
    salt*: seq[byte]
    info*: seq[byte]
    iterations*: int
  
  CryptoContext* = ref object
    masterKey: seq[byte]
    sessionKeys: Table[string, SessionKey]
    rotationInterval: Duration
    lastRotation: DateTime
  
  SessionKey* = object
    key*: seq[byte]
    createdAt*: DateTime
    usageCount*: int
    maxUsage*: int

const
  KeySize* = 32
  NonceSize* = 24
  TagSize* = 16
  MaxAadSize* = 16384  # 16KB
  DefaultKeyRotationInterval* = initDuration(hours = 1)
  MaxKeyUsage* = 10000

# Inicialización del módulo
proc initCrypto*() =
  ## Inicializa la librería de criptografía
  if sodium_init() < 0:
    raise newException(CryptoError, "Failed to initialize libsodium")
  randomize()

# Generación segura de números aleatorios
proc secureRandom*(size: int): seq[byte] =
  ## Genera bytes aleatorios criptográficamente seguros
  result = newSeq[byte](size)
  randombytes_buf(addr result[0], size.csize_t)

# Derivación de claves
proc deriveKey*(masterKey: seq[byte], salt: seq[byte], info: seq[byte] = @[]): seq[byte] =
  ## Deriva una clave usando HKDF-SHA256
  if masterKey.len != KeySize:
    raise newException(CryptoError, "Master key must be 32 bytes")
  
  if salt.len < 16:
    raise newException(CryptoError, "Salt must be at least 16 bytes")
  
  result = newSeq[byte](KeySize)
  
  # HKDF Extract
  var prk: array[32, byte]
  let hmacCtx = hmac.new(sha256, salt)
  hmacCtx.update(masterKey)
  hmacCtx.finish(prk)
  
  # HKDF Expand
  var okm = newSeq[byte](KeySize)
  var counter: byte = 1
  let expandCtx = hmac.new(sha256, prk)
  
  if info.len > 0:
    expandCtx.update(info)
  expandCtx.update([counter])
  expandCtx.finish(okm)
  
  result = okm

# Función principal de cifrado
proc encryptPayload*(data: seq[byte], key: seq[byte], aad: seq[byte] = @[]): seq[byte] {.raises: [CryptoError].} =
  ## Cifra un payload usando XChaCha20-Poly1305 con AAD
  
  # Validación de precondiciones
  if key.len != KeySize:
    raise newException(CryptoError, 
      "Invalid key size: expected " & $KeySize & " bytes, got " & $key.len)
  
  if aad.len > MaxAadSize:
    raise newException(CryptoError, 
      "AAD too large: maximum " & $MaxAadSize & " bytes, got " & $aad.len)
  
  if data.len == 0:
    raise newException(CryptoError, "Cannot encrypt empty data")
  
  # Generar nonce aleatorio
  let nonce = secureRandom(NonceSize)
  
  # Preparar buffer de salida: nonce + ciphertext + tag
  let ciphertextLen = data.len + TagSize
  result = newSeq[byte](NonceSize + ciphertextLen)
  
  # Copiar nonce al inicio del resultado
  copyMem(addr result[0], unsafeAddr nonce[0], NonceSize)
  
  # Cifrar datos
  var ciphertext = addr result[NonceSize]
  var ciphertextLenOut: culonglong
  
  let ret = crypto_aead_xchacha20poly1305_ietf_encrypt(
    ciphertext,
    addr ciphertextLenOut,
    unsafeAddr data[0],
    data.len.culonglong,
    if aad.len > 0: unsafeAddr aad[0] else: nil,
    aad.len.culonglong,
    nil,  # No secret nonce
    unsafeAddr nonce[0],
    unsafeAddr key[0]
  )
  
  if ret != 0:
    raise newException(CryptoError, "Encryption failed")
  
  # Verificar postcondición
  assert ciphertextLenOut.int == ciphertextLen
  
  # Limpiar datos sensibles de la memoria
  zeroMem(unsafeAddr nonce[0], NonceSize)
  
  debug "Payload encrypted", 
    dataSize = data.len,
    aadSize = aad.len,
    outputSize = result.len

proc decryptPayload*(ciphertext: seq[byte], key: seq[byte], aad: seq[byte] = @[]): seq[byte] {.raises: [CryptoError].} =
  ## Descifra un payload cifrado con XChaCha20-Poly1305
  
  if key.len != KeySize:
    raise newException(CryptoError, "Invalid key size")
  
  if ciphertext.len < NonceSize + TagSize:
    raise newException(CryptoError, "Ciphertext too short")
  
  # Extraer nonce
  var nonce = newSeq[byte](NonceSize)
  copyMem(addr nonce[0], unsafeAddr ciphertext[0], NonceSize)
  
  # Preparar buffer para datos descifrados
  let plaintextLen = ciphertext.len - NonceSize - TagSize
  result = newSeq[byte](plaintextLen)
  
  var plaintextLenOut: culonglong
  
  let ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
    addr result[0],
    addr plaintextLenOut,
    nil,  # No secret nonce
    unsafeAddr ciphertext[NonceSize],
    (ciphertext.len - NonceSize).culonglong,
    if aad.len > 0: unsafeAddr aad[0] else: nil,
    aad.len.culonglong,
    unsafeAddr nonce[0],
    unsafeAddr key[0]
  )
  
  if ret != 0:
    raise newException(CryptoError, "Decryption failed or authentication tag invalid")
  
  # Limpiar datos sensibles
  zeroMem(addr nonce[0], NonceSize)
  
  debug "Payload decrypted", 
    ciphertextSize = ciphertext.len,
    plaintextSize = result.len

# Gestión de contexto criptográfico
proc newCryptoContext*(masterKey: seq[byte], rotationInterval = DefaultKeyRotationInterval): CryptoContext =
  ## Crea un nuevo contexto criptográfico con gestión de claves
  if masterKey.len != KeySize:
    raise newException(CryptoError, "Master key must be 32 bytes")
  
  result = CryptoContext(
    masterKey: masterKey,
    sessionKeys: initTable[string, SessionKey](),
    rotationInterval: rotationInterval,
    lastRotation: now()
  )

proc getOrCreateSessionKey*(ctx: CryptoContext, sessionId: string): seq[byte] =
  ## Obtiene o crea una clave de sesión
  
  # Verificar si necesita rotación
  if now() - ctx.lastRotation > ctx.rotationInterval:
    ctx.sessionKeys.clear()
    ctx.lastRotation = now()
    info "Session keys rotated"
  
  if sessionId in ctx.sessionKeys:
    var sessionKey = ctx.sessionKeys[sessionId]
    
    # Verificar límite de uso
    if sessionKey.usageCount >= sessionKey.maxUsage:
      # Regenerar clave
      let salt = secureRandom(32)
      let info = sessionId.toBytes
      sessionKey.key = deriveKey(ctx.masterKey, salt, info)
      sessionKey.createdAt = now()
      sessionKey.usageCount = 0
      ctx.sessionKeys[sessionId] = sessionKey
      info "Session key regenerated", sessionId = sessionId
    else:
      inc sessionKey.usageCount
      ctx.sessionKeys[sessionId] = sessionKey
    
    result = sessionKey.key
  else:
    # Crear nueva clave de sesión
    let salt = secureRandom(32)
    let info = sessionId.toBytes
    let key = deriveKey(ctx.masterKey, salt, info)
    
    ctx.sessionKeys[sessionId] = SessionKey(
      key: key,
      createdAt: now(),
      usageCount: 1,
      maxUsage: MaxKeyUsage
    )
    
    result = key
    info "New session key created", sessionId = sessionId

# Funciones auxiliares para AAD
proc generateAadForMessage*(nodeId: string, messageType: string, timestamp: int64 = 0): seq[byte] =
  ## Genera AAD para un mensaje con contexto
  let ts = if timestamp == 0: epochTime().int64 else: timestamp
  let aadString = nodeId & "|" & messageType & "|" & $ts
  result = aadString.toBytes
  
  if result.len > MaxAadSize:
    result = result[0..<MaxAadSize]

# Limpieza segura de memoria
proc secureWipe*(data: var seq[byte]) =
  ## Limpia de forma segura datos sensibles de la memoria
  if data.len > 0:
    zeroMem(addr data[0], data.len)
    data.setLen(0)

# Ejemplo de uso con manejo robusto de errores
proc enviarMensajeSeguro*(node: P2PNode, mensaje: string, ctx: CryptoContext) =
  ## Envía un mensaje cifrado de forma segura
  let data = mensaje.toBytes
  let sessionId = node.peerId
  
  var claveSesion: seq[byte]
  var ciphertext: seq[byte]
  
  try:
    # Obtener clave de sesión
    claveSesion = ctx.getOrCreateSessionKey(sessionId)
    
    # Generar AAD con contexto
    let aad = generateAadForMessage(
      node.id,
      "message",
      epochTime().int64
    )
    
    # Cifrar payload
    ciphertext = encryptPayload(data, claveSesion, aad)
    
    # Enviar mensaje cifrado
    node.send(ciphertext)
    
    debug "Secure message sent",
      nodeId = node.id,
      messageSize = data.len,
      ciphertextSize = ciphertext.len
    
  except CryptoError as e:
    error "Encryption failed", 
      error = e.msg,
      nodeId = node.id
    
    # Intentar recuperación
    try:
      # Limpiar claves comprometidas
      ctx.sessionKeys.del(sessionId)
      
      # Reintentar con nueva clave
      claveSesion = ctx.getOrCreateSessionKey(sessionId)
      let aad = generateAadForMessage(node.id, "message_retry")
      ciphertext = encryptPayload(data, claveSesion, aad)
      node.send(ciphertext)
      
      info "Message sent after recovery"
      
    except CryptoError as e2:
      error "Recovery failed", error = e2.msg
      raise
  
  finally:
    # Limpiar datos sensibles
    secureWipe(claveSesion)

# Tests unitarios
when isMainModule:
  import unittest
  
  suite "Crypto Module Tests":
    setup:
      initCrypto()
    
    test "Encrypt and decrypt payload":
      let key = secureRandom(KeySize)
      let data = "Hello, World!".toBytes
      let aad = "metadata".toBytes
      
      let encrypted = encryptPayload(data, key, aad)
      let decrypted = decryptPayload(encrypted, key, aad)
      
      check decrypted == data
    
    test "Invalid key size":
      let invalidKey = secureRandom(16)  # Wrong size
      let data = "test".toBytes
      
      expect CryptoError:
        discard encryptPayload(data, invalidKey)
    
    test "AAD validation":
      let key = secureRandom(KeySize)
      let data = "test".toBytes
      let largeAad = newSeq[byte](MaxAadSize + 1)
      
      expect CryptoError:
        discard encryptPayload(data, key, largeAad)
    
    test "Session key rotation":
      let masterKey = secureRandom(KeySize)
      let ctx = newCryptoContext(masterKey, initDuration(milliseconds = 100))
      
      let key1 = ctx.getOrCreateSessionKey("session1")
      sleep(150)
      let key2 = ctx.getOrCreateSessionKey("session1")
      
      check key1 != key2  # Keys should 
