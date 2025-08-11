# src/crypto.nim
# Módulo que implementa funciones criptográficas para cifrado de payloads usando XChaCha20-Poly1305.
# Incluye manejo de claves derivadas con HKDF y verificación de integridad.

import nimcrypto/xchachapoly
import nimcrypto/sysrand
import nimcrypto/hkdf
import nimcrypto/sha2  # Para HKDF-SHA256
import sequtils  # Para operaciones con secuencias

# Excepciones definidas
type
  CryptoError* = object of CatchableError

# Configuraciones
const
  KEY_SIZE = 32  # Tamaño de clave en bytes
  NONCE_SIZE = 24  # Tamaño de nonce en bytes para XChaCha20
  TAG_SIZE = 16  # Tamaño del tag de autenticación
  MAX_AAD_SIZE = 16384  # 16KB máximo para AAD

# Proc principal para cifrado
proc encryptPayload*(data: seq[byte], key: seq[byte], aad: seq[byte] = @[]): seq[byte] {.raises: [CryptoError].} =
  ## Cifra un payload usando XChaCha20-Poly1305 con datos autenticados adicionales (AAD).
  
  if key.len != KEY_SIZE:
    raise newException(CryptoError, "La clave debe tener exactamente " & $KEY_SIZE & " bytes")
  
  if aad.len > MAX_AAD_SIZE:
    raise newException(CryptoError, "Los datos AAD exceden el límite de " & $MAX_AAD_SIZE & " bytes")
  
  var nonce: array[NONCE_SIZE, byte]
  if randomBytes(nonce) != NONCE_SIZE:
    raise newException(CryptoError, "Fallo al generar nonce aleatorio")
  
  var ctx: XChaChaPoly
  if not ctx.init(key, nonce):
    raise newException(CryptoError, "Fallo en la inicialización del contexto de cifrado")
  
  ctx.updateAAD(aad)
  
  var ciphertext = newSeq[byte](data.len)
  ctx.encrypt(data, ciphertext)
  
  var tag: array[TAG_SIZE, byte]
  ctx.getTag(tag)
  
  ctx.clear()
  
  # Resultado: nonce + ciphertext + tag
  result = nonce.toSeq() & ciphertext & tag.toSeq()

# Proc para descifrado (ampliación para completitud)
proc decryptPayload*(encrypted: seq[byte], key: seq[byte], aad: seq[byte] = @[]): seq[byte] {.raises: [CryptoError].} =
  ## Descifra un payload cifrado con XChaCha20-Poly1305 y verifica la integridad.
  
  let minLen = NONCE_SIZE + TAG_SIZE
  if encrypted.len < minLen:
    raise newException(CryptoError, "Datos cifrados demasiado cortos")
  
  if key.len != KEY_SIZE:
    raise newException(CryptoError, "La clave debe tener exactamente " & $KEY_SIZE & " bytes")
  
  if aad.len > MAX_AAD_SIZE:
    raise newException(CryptoError, "Los datos AAD exceden el límite de " & $MAX_AAD_SIZE & " bytes")
  
  let nonce = encrypted[0 ..< NONCE_SIZE]
  let ciphertextLen = encrypted.len - NONCE_SIZE - TAG_SIZE
  let ciphertext = encrypted[NONCE_SIZE ..< NONCE_SIZE + ciphertextLen]
  let providedTag = encrypted[^TAG_SIZE .. ^1]
  
  var ctx: XChaChaPoly
  if not ctx.init(key, nonce):
    raise newException(CryptoError, "Fallo en la inicialización del contexto de descifrado")
  
  ctx.updateAAD(aad)
  
  var plaintext = newSeq[byte](ciphertextLen)
  ctx.decrypt(ciphertext, plaintext)
  
  var computedTag: array[TAG_SIZE, byte]
  ctx.getTag(computedTag)
  
  ctx.clear()
  
  if computedTag != providedTag.toOpenArrayByte(0, TAG_SIZE-1):
    raise newException(CryptoError, "Fallo en la verificación de integridad (tag no coincide)")
  
  result = plaintext

# Proc para derivación de claves usando HKDF-SHA256
proc deriveSessionKey*(masterKey: seq[byte], salt: seq[byte], info: string): seq[byte] {.raises: [CryptoError].} =
  ## Deriva una clave de sesión a partir de una clave maestra usando HKDF-SHA256.
  
  if masterKey.len == 0:
    raise newException(CryptoError, "Clave maestra vacía")
  
  var output: array[KEY_SIZE, byte]
  hkdf(sha256, masterKey, salt, info.toBytes(), output)
  
  result = output.toSeq()

# Ejemplo de uso seguro (como comentario)
# proc enviarMensajeSeguro(node: P2PNode, mensaje: string, claveSesion: seq[byte]) =
#   let data = mensaje.toBytes
#   let aad = generateAadForMessage(node, mensaje)  # Contexto adicional (implementar en otro módulo)
#   try:
#     let ciphertext = encryptPayload(data, claveSesion, aad)
#     node.enviar(ciphertext)
#   except CryptoError as e:
#     logError("Fallo en cifrado: " & e.msg)
#     # Intentar recuperación
#     reiniciarSesionCrypto(node)

# Notas adicionales:
# - Para rotación de claves: Implementar un temporizador que derive nuevas claves periódicamente usando deriveSessionKey con info único (e.g., "session_" & timestamp).
# - Almacenamiento seguro: En Nim, considerar usar secure memory via lockMem/unlockMem de posix para evitar swap, pero requiere manejo manual.
# - Forward secrecy: Usar claves efímeras derivadas por sesión y descartarlas después de uso.
# - Verificación de integridad: Siempre usar decryptPayload para validar antes de procesar datos recibidos.
# - Manejo de errores: En producción, capturar CryptoError y fallback a modos seguros o terminación.
