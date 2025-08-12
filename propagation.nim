import asyncdispatch, asyncnet, net, strutils, sequtils, times, random, json
import std/[strformat, logging, re, tables]

# Tipos de datos para información de servicios y hosts
type
  ServiceInfo* = object
    port*: int
    protocol*: string
    name*: string
    version*: string
    banner*: string
    isVulnerable*: bool
    cveList*: seq[string]

type
  OSFingerprint* = object
    vendor*: string
    os*: string
    version*: string
    deviceType*: string
    confidence*: float

type
  HostInfo* = object
    ip*: string
    mac*: string
    isUp*: bool
    os*: OSFingerprint
    services*: seq[ServiceInfo]
    lastScanned*: int64
    confidence*: float

# Configuración para escaneo sigiloso
type
  ScanConfig = object
    rateLimit: int              # Paquetes por segundo
    fragmentPackets: bool       # Fragmentar paquetes
    randomizeOrder: bool        # Aleatorizar orden de IPs
    variableIntervals: bool     # Intervalos variables
    spoofMac: bool             # Spoofear MAC
    maxConcurrent: int         # Conexiones concurrentes máximas

# Base de datos de servicios conocidos
let COMMON_PORTS = {
  21: ("ftp", "File Transfer Protocol"),
  22: ("ssh", "Secure Shell"),
  23: ("telnet", "Telnet"),
  25: ("smtp", "Simple Mail Transfer Protocol"),
  53: ("dns", "Domain Name System"),
  80: ("http", "Hypertext Transfer Protocol"),
  110: ("pop3", "Post Office Protocol v3"),
  143: ("imap", "Internet Message Access Protocol"),
  443: ("https", "HTTP Secure"),
  993: ("imaps", "IMAP Secure"),
  995: ("pop3s", "POP3 Secure"),
  3389: ("rdp", "Remote Desktop Protocol"),
  5432: ("postgresql", "PostgreSQL Database"),
  3306: ("mysql", "MySQL Database"),
  1433: ("mssql", "Microsoft SQL Server"),
  6379: ("redis", "Redis Database"),
  27017: ("mongodb", "MongoDB Database")
}.toTable

# Patrones de OS fingerprinting
let OS_SIGNATURES = {
  "Linux": @[
    re"Linux",
    re"Ubuntu",
    re"CentOS",
    re"Red Hat",
    re"RHEL"
  ],
  "Windows": @[
    re"Windows",
    re"Microsoft",
    re"IIS",
    re"Active Directory"
  ],
  "macOS": @[
    re"Darwin",
    re"Mac OS",
    re"macOS",
    re"Apple"
  ],
  "FreeBSD": @[
    re"FreeBSD",
    re"BSD"
  ]
}.toTable

# Vulnerabilidades conocidas por servicio
let VULNERABILITY_DB = {
  "ssh": @[
    ("OpenSSH < 7.4", @["CVE-2016-10009", "CVE-2016-10010"]),
    ("OpenSSH < 8.3", @["CVE-2020-14145"])
  ],
  "http": @[
    ("Apache < 2.4.49", @["CVE-2021-41773"]),
    ("nginx < 1.20.1", @["CVE-2021-23017"])
  ],
  "ftp": @[
    ("vsftpd 2.3.4", @["CVE-2011-2523"]),
    ("ProFTPD < 1.3.5", @["CVE-2015-3306"])
  ]
}.toTable

# Utilidades de red
proc parseSubnet(subnet: string): seq[string] =
  ## Convierte una subred CIDR en lista de IPs
  result = @[]
  let parts = subnet.split("/")
  if parts.len != 2:
    return
  
  let baseIp = parts[0]
  let prefixLen = parseInt(parts[1])
  let ipParts = baseIp.split(".").mapIt(parseInt(it))
  
  if prefixLen >= 24:
    # Subred /24 o mayor
    let hosts = 1 shl (32 - prefixLen)
    for i in 1..<hosts-1:  # Excluir red y broadcast
      let lastOctet = (ipParts[3] and (0xFF shl (32 - prefixLen))) + i
      if lastOctet <= 255:
        result.add(fmt"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}.{lastOctet}")

proc isPortOpen(ip: string, port: int, timeout: float): Future[bool] {.async.} =
  ## Verifica si un puerto está abierto usando conexión TCP
  try:
    var socket = newAsyncSocket()
    let connected = await socket.connect(ip, Port(port)).withTimeout(int(timeout * 1000))
    socket.close()
    return connected
  except:
    return false

proc getServiceBanner(ip: string, port: int, timeout: float): Future[string] {.async.} =
  ## Obtiene el banner de un servicio
  try:
    var socket = newAsyncSocket()
    await socket.connect(ip, Port(port)).withTimeout(int(timeout * 1000))
    
    # Enviar probe específico según el puerto
    case port:
      of 21:  # FTP
        await socket.send("USER anonymous\r\n")
      of 25:  # SMTP
        await socket.send("EHLO test\r\n")
      of 80, 443:  # HTTP/HTTPS
        await socket.send("HEAD / HTTP/1.0\r\n\r\n")
      else:
        discard
    
    # Intentar recibir banner
    let banner = await socket.recv(512).withTimeout(2000)
    socket.close()
    return banner.strip()
    
  except:
    return ""

proc identifyService(port: int, banner: string): ServiceInfo =
  ## Identifica un servicio basado en puerto y banner
  result = ServiceInfo(
    port: port,
    protocol: "tcp",
    banner: banner,
    isVulnerable: false,
    cveList: @[]
  )
  
  # Identificar servicio por puerto conocido
  if COMMON_PORTS.hasKey(port):
    let (name, desc) = COMMON_PORTS[port]
    result.name = name
  else:
    result.name = "unknown"
  
  # Analizar banner para obtener versión
  if banner.len > 0:
    # Patrones comunes para extraer versión
    let versionPatterns = @[
      re"([a-zA-Z\-]+)[\s/]+([\d\.]+)",
      re"Server:\s*([^\s]+)\s*([\d\.]*)",
      re"([a-zA-Z]+)\s*[\s/]*([\d\.]+)"
    ]
    
    for pattern in versionPatterns:
      var matches: array[3, string]
      if match(banner, pattern, matches):
        result.name = matches[0].toLowerAscii()
        result.version = matches[1]
        break
  
  # Verificar vulnerabilidades conocidas
  if VULNERABILITY_DB.hasKey(result.name) and result.version.len > 0:
    for (vulnVersion, cves) in VULNERABILITY_DB[result.name]:
      if vulnVersion.contains(result.version):
        result.isVulnerable = true
        result.cveList = cves

proc performOSFingerprinting(ip: string, services: seq[ServiceInfo]): OSFingerprint =
  ## Realiza fingerprinting del sistema operativo
  result = OSFingerprint(
    vendor: "Unknown",
    os: "Unknown",
    version: "Unknown",
    deviceType: "Unknown",
    confidence: 0.0
  )
  
  var scoreTable = initTable[string, float]()
  
  # Analizar banners de servicios
  for service in services:
    if service.banner.len > 0:
      for osName, patterns in OS_SIGNATURES:
        for pattern in patterns:
          if match(service.banner, pattern):
            if not scoreTable.hasKey(osName):
              scoreTable[osName] = 0.0
            scoreTable[osName] += 0.2
  
  # Analizar puertos típicos
  let openPorts = services.mapIt(it.port)
  
  # Windows indicators
  if 3389 in openPorts or 445 in openPorts or 135 in openPorts:
    if not scoreTable.hasKey("Windows"):
      scoreTable["Windows"] = 0.0
    scoreTable["Windows"] += 0.3
  
  # Linux indicators  
  if 22 in openPorts:
    if not scoreTable.hasKey("Linux"):
      scoreTable["Linux"] = 0.0
    scoreTable["Linux"] += 0.2
  
  # Seleccionar OS con mayor puntuación
  var maxScore = 0.0
  var detectedOS = "Unknown"
  
  for os, score in scoreTable:
    if score > maxScore:
      maxScore = score
      detectedOS = os
  
  if maxScore > 0.3:
    result.os = detectedOS
    result.confidence = min(maxScore, 1.0)
    
    case detectedOS:
      of "Windows":
        result.vendor = "Microsoft"
        result.deviceType = "PC"
      of "Linux":
        result.vendor = "Various"
        result.deviceType = "Server/PC"
      of "macOS":
        result.vendor = "Apple"
        result.deviceType = "Mac"

proc scanSingleHost(ip: string, portFilter: seq[int], timeout: float, config: ScanConfig): Future[HostInfo] {.async.} =
  ## Escanea un solo host de forma sigilosa
  result = HostInfo(
    ip: ip,
    mac: "",
    isUp: false,
    lastScanned: getTime().toUnix(),
    confidence: 0.0,
    services: @[]
  )
  
  # Determinar puertos a escanear
  let portsToScan = if portFilter.len > 0:
    portFilter
  else:
    @[21, 22, 23, 25, 53, 80, 135, 139, 143, 443, 445, 993, 995, 3389, 5432, 3306]
  
  # Aleatorizar orden de puertos si está habilitado
  var scanPorts = portsToScan
  if config.randomizeOrder:
    shuffle(scanPorts)
  
  # Rate limiting
  let delayBetweenPorts = if config.rateLimit > 0:
    1000 div config.rateLimit  # ms de delay
  else:
    100
  
  var openServices: seq[ServiceInfo] = @[]
  var semaphore = 0
  
  # Escanear puertos
  for port in scanPorts:
    # Controlar concurrencia
    while semaphore >= config.maxConcurrent:
      await sleepAsync(10)
    
    inc(semaphore)
    
    # Escaneo asíncrono del puerto
    let isOpen = await isPortOpen(ip, port, timeout)
    
    if isOpen:
      result.isUp = true
      
      # Obtener banner del servicio
      let banner = await getServiceBanner(ip, port, timeout)
      
      # Identificar servicio
      let service = identifyService(port, banner)
      openServices.add(service)
      
      echo fmt"  Puerto {port}/tcp abierto: {service.name}"
    
    dec(semaphore)
    
    # Rate limiting y intervalos variables
    if config.variableIntervals:
      let randomDelay = rand(delayBetweenPorts div 2..delayBetweenPorts * 2)
      await sleepAsync(randomDelay)
    else:
      await sleepAsync(delayBetweenPorts)
  
  # Si el host está activo, realizar fingerprinting
  if result.isUp:
    result.services = openServices
    result.os = performOSFingerprinting(ip, openServices)
    result.confidence = if openServices.len > 0: 0.8 else: 0.5
    
    echo fmt"Host {ip} activo - OS: {result.os.os} (confianza: {result.confidence:.2f})"

proc scanLanTargets*(subnet: string, portFilter: seq[int] = @[], timeout: float = 2.0): Future[seq[HostInfo]] {.async, raises: [].} =
  ## Escanea la subred local (LAN) para descubrir hosts activos con información detallada
  result = @[]
  
  try:
    echo fmt"Iniciando escaneo de subred: {subnet}"
    
    # Configuración de escaneo sigiloso
    let config = ScanConfig(
      rateLimit: 10,           # 10 paquetes por segundo
      fragmentPackets: false,   # Deshabilitado por simplicidad
      randomizeOrder: true,     # Aleatorizar orden
      variableIntervals: true,  # Intervalos variables
      spoofMac: false,         # Deshabilitado por simplicidad  
      maxConcurrent: 5         # 5 conexiones concurrentes
    )
    
    # Parsear subred a lista de IPs
    let targetIPs = parseSubnet(subnet)
    
    if targetIPs.len == 0:
      echo "No se pudieron generar IPs de la subred"
      return
    
    echo fmt"Escaneando {targetIPs.len} hosts..."
    
    # Aleatorizar orden de IPs si está habilitado
    var scanIPs = targetIPs
    if config.randomizeOrder:
      shuffle(scanIPs)
    
    # Escanear hosts con concurrencia limitada
    var activeTasks = 0
    var results: seq[HostInfo] = @[]
    
    for ip in scanIPs:
      # Controlar concurrencia
      while activeTasks >= config.maxConcurrent:
        await sleepAsync(100)
      
      inc(activeTasks)
      
      # Escaneo asíncrono
      let future = scanSingleHost(ip, portFilter, timeout, config)
      
      future.addCallback do ():
        dec(activeTasks)
        let hostInfo = future.read()
        if hostInfo.isUp:
          results.add(hostInfo)
    
    # Esperar a que terminen todas las tareas
    while activeTasks > 0:
      await sleepAsync(100)
    
    result = results
    echo fmt"Escaneo completado. {result.len} hosts activos encontrados."
    
  except:
    echo fmt"Error durante el escaneo: {getCurrentExceptionMsg()}"
    result = @[]

# Funciones auxiliares adicionales
proc scanSpecificHosts*(hosts: seq[string], portFilter: seq[int] = @[], timeout: float = 2.0): Future[seq[HostInfo]] {.async.} =
  ## Escanea una lista específica de hosts
  result = @[]
  
  let config = ScanConfig(
    rateLimit: 15,
    fragmentPackets: false,
    randomizeOrder: true,
    variableIntervals: true,
    spoofMac: false,
    maxConcurrent: 8
  )
  
  echo fmt"Escaneando {hosts.len} hosts específicos..."
  
  for host in hosts:
    try:
      let hostInfo = await scanSingleHost(host, portFilter, timeout, config)
      if hostInfo.isUp:
        result.add(hostInfo)
    except:
      echo fmt"Error escaneando {host}: {getCurrentExceptionMsg()}"

proc generateScanReport*(hosts: seq[HostInfo]): string =
  ## Genera un reporte detallado del escaneo
  result = "=== REPORTE DE ESCANEO DE RED ===\n\n"
  result.add(fmt"Fecha: {getTime().format('yyyy-MM-dd HH:mm:ss')}\n")
  result.add(fmt"Hosts escaneados: {hosts.len}\n\n")
  
  for host in hosts:
    result.add(fmt"Host: {host.ip}\n")
    result.add(fmt"  Estado: {'Activo' if host.isUp else 'Inactivo'}\n")
    
    if host.isUp:
      result.add(fmt"  OS: {host.os.os} {host.os.version} (Confianza: {host.os.confidence:.2f})\n")
      result.add(fmt"  Vendor: {host.os.vendor}\n")
      result.add(fmt"  Tipo: {host.os.deviceType}\n")
      result.add(fmt"  Servicios ({host.services.len}):\n")
      
      for service in host.services:
        result.add(fmt"    {service.port}/{service.protocol} - {service.name}")
        if service.version.len > 0:
          result.add(fmt" {service.version}")
        if service.isVulnerable:
          result.add(" [VULNERABLE]")
          for cve in service.cveList:
            result.add(fmt" {cve}")
        result.add("\n")
        
        if service.banner.len > 0:
          result.add(fmt"      Banner: {service.banner[0..min(100, service.banner.len-1)]}\n")
    
    result.add("\n")

proc exportScanResults*(hosts: seq[HostInfo], filename: string, format: string = "json"): Future[bool] {.async.} =
  ## Exporta los resultados del escaneo en diferentes formatos
  try:
    case format.toLowerAscii():
      of "json":
        let jsonData = %*{
          "scan_date": getTime().format("yyyy-MM-dd HH:mm:ss"),
          "total_hosts": hosts.len,
          "active_hosts": hosts.filterIt(it.isUp).len,
          "hosts": hosts
        }
        writeFile(filename, jsonData.pretty())
        
      of "csv":
        var csvContent = "IP,Status,OS,OS_Version,OS_Confidence,Services_Count,Open_Ports\n"
        for host in hosts:
          let openPorts = host.services.mapIt($it.port).join(";")
          csvContent.add(fmt"{host.ip},{if host.isUp: 'Up' else: 'Down'},{host.os.os},{host.os.version},{host.os.confidence},{host.services.len},\"{openPorts}\"\n")
        writeFile(filename, csvContent)
        
      of "txt":
        let report = generateScanReport(hosts)
        writeFile(filename, report)
        
      else:
        echo "Formato no soportado. Use: json, csv, txt"
        return false
    
    echo fmt"Resultados exportados a: {filename}"
    return true
    
  except:
    echo fmt"Error exportando resultados: {getCurrentExceptionMsg()}"
    return false

proc detectVulnerableServices*(hosts: seq[HostInfo]): seq[tuple[host: string, service: ServiceInfo]] =
  ## Detecta servicios vulnerables en los hosts escaneados
  result = @[]
  
  for host in hosts:
    if not host.isUp:
      continue
      
    for service in host.services:
      if service.isVulnerable:
        result.add((host: host.ip, service: service))

proc suggestSecurityMeasures*(hosts: seq[HostInfo]): seq[string] =
  ## Sugiere medidas de seguridad basadas en el escaneo
  result = @[]
  var findings = initTable[string, int]()
  
  for host in hosts:
    if not host.isUp:
      continue
    
    # Contar servicios por tipo
    for service in host.services:
      let key = service.name
      findings[key] = findings.getOrDefault(key, 0) + 1
      
      # Verificaciones específicas
      case service.name:
        of "telnet":
          result.add("⚠️  Telnet detectado - Considere migrar a SSH")
        of "ftp":
          if not service.name.contains("sftp"):
            result.add("⚠️  FTP sin cifrar detectado - Considere SFTP/FTPS")
        of "http":
          if 443 notin host.services.mapIt(it.port):
            result.add("⚠️  HTTP sin HTTPS - Implemente certificados SSL/TLS")
        of "rdp":
          result.add("⚠️  RDP detectado - Asegúrese de usar autenticación fuerte")
  
  # Estadísticas generales
  let activeHosts = hosts.filterIt(it.isUp)
  if activeHosts.len > 0:
    result.add(fmt"📊 {activeHosts.len} hosts activos detectados")
    
    let vulnServices = detectVulnerableServices(hosts)
    if vulnServices.len > 0:
      result.add(fmt"🔴 {vulnServices.len} servicios vulnerables detectados")
    
    if findings.hasKey("ssh"):
      result.add(fmt"✅ SSH encontrado en {findings['ssh']} hosts")

# Funciones de monitoreo continuo
proc startContinuousMonitoring*(subnet: string, interval: int = 300): Future[void] {.async.} =
  ## Inicia monitoreo continuo de la red
  echo fmt"Iniciando monitoreo continuo de {subnet} cada {interval} segundos"
  
  var lastScan: seq[HostInfo] = @[]
  
  while true:
    try:
      echo "\n=== NUEVO CICLO DE MONITOREO ==="
      let currentScan = await scanLanTargets(subnet)
      
      # Comparar con escaneo anterior
      if lastScan.len > 0:
        let previousIPs = lastScan.filterIt(it.isUp).mapIt(it.ip)
        let currentIPs = currentScan.filterIt(it.isUp).mapIt(it.ip)
        
        # Nuevos hosts detectados
        let newHosts = currentIPs.filterIt(it notin previousIPs)
        if newHosts.len > 0:
          echo fmt"🆕 Nuevos hosts detectados: {newHosts.join(', ')}"
        
        # Hosts que desaparecieron
        let missingHosts = previousIPs.filterIt(it notin currentIPs)
        if missingHosts.len > 0:
          echo fmt"❌ Hosts desconectados: {missingHosts.join(', ')}"
      
      lastScan = currentScan
      
      # Detectar cambios en servicios
      let vulnServices = detectVulnerableServices(currentScan)
      if vulnServices.len > 0:
        echo "🚨 SERVICIOS VULNERABLES DETECTADOS:"
        for (host, service) in vulnServices:
          echo fmt"  {host}:{service.port} - {service.name} {service.version}"
          for cve in service.cveList:
            echo fmt"    CVE: {cve}"
      
      await sleepAsync(interval * 1000)
      
    except:
      echo fmt"Error en monitoreo: {getCurrentExceptionMsg()}"
      await sleepAsync(60000)  # Esperar 1 minuto antes de reintentar

proc performAdvancedScan*(target: string, scanType: string = "comprehensive"): Future[HostInfo] {.async.} =
  ## Realiza un escaneo avanzado de un host específico
  echo fmt"Realizando escaneo {scanType} de {target}"
  
  let config = ScanConfig(
    rateLimit: 50,  # Más agresivo para escaneo individual
    fragmentPackets: false,
    randomizeOrder: false,
    variableIntervals: false,
    spoofMac: false,
    maxConcurrent: 10
  )
  
  var portList: seq[int] = @[]
  
  case scanType:
    of "quick":
      portList = @[21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]
    of "comprehensive":
      # Top 1000 ports (simulado con una muestra)
      portList = @[
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
        1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017
      ]
      for i in 1000..1100:  # Puertos adicionales
        portList.add(i)
    of "stealth":
      portList = @[80, 443, 22, 21]  # Puertos básicos
      config.rateLimit = 5  # Muy lento
    else:
      portList = @[22, 80, 443]
  
  result = await scanSingleHost(target, portList, 3.0, config)
  
  echo fmt"Escaneo {scanType} completado para {target}"
  echo fmt"Servicios encontrados: {result.services.len}"

# Función de prueba y ejemplo de uso
proc testScanModule*(): Future[void] {.async.} =
  ## Función de prueba para el módulo de escaneo
  echo "=== PRUEBA DEL MÓDULO DE PROPAGACIÓN ==="
  
  # Escanear subred local común
  let results = await scanLanTargets("192.168.1.0/24", @[22, 80, 443], 2.0)
  
  echo fmt"\nResultados encontrados: {results.len} hosts activos"
  
  # Generar reporte
  let report = generateScanReport(results)
  echo "\n" & report
  
  # Detectar vulnerabilidades
  let vulnServices = detectVulnerableServices(results)
  if vulnServices.len > 0:
    echo "\n=== SERVICIOS VULNERABLES ==="
    for (host, service) in vulnServices:
      echo fmt"{host}:{service.port} - {service.name} {service.version}"
  
  # Sugerir medidas de seguridad
  let suggestions = suggestSecurityMeasures(results)
  if suggestions.len > 0:
    echo "\n=== RECOMENDACIONES DE SEGURIDAD ==="
    for suggestion in suggestions:
      echo suggestion

# Exportar resultados automáticamente
proc autoExportResults*(hosts: seq[HostInfo], baseName: string = "scan_results"): Future[void] {.async.} =
  ## Exporta automáticamente en múltiples formatos
  let timestamp = getTime().format("yyyyMMdd_HHmmss")
  
  discard await exportScanResults(hosts, fmt"{baseName}_{timestamp}.json", "json")
  discard await exportScanResults(hosts, fmt"{baseName}_{timestamp}.csv", "csv")
  discard await exportScanResults(hosts, fmt"{baseName}_{timestamp}.txt", "txt")
