import asyncdispatch
import json
import os
import osproc
import strutils
import times

type
  SandboxMethod* = enum
    VMArtifacts, HardwareInconsistency, TimingAnalysis,
    ProcessAnalysis, RegistryAnalysis, UserActivity,
    NetworkFingerprint, MouseMovement, ScreenshotAnalysis

  SandboxDetectionResult* = object
    isSandbox*: bool
    confidence*: float          # 0.0-1.0
    detectedMethods*: seq[SandboxMethod]
    details*: JsonNode          # Resultados detallados por método
    recommendedAction*: string  # Qué hacer si es sandbox

proc checkVMArtifacts(details: var JsonNode): bool =
  ## Checks for common VM artifacts in IoT Linux environments.
  var detected = false
  var info: seq[string] = @[]
  
  if fileExists("/proc/cpuinfo"):
    let cpuinfo = readFile("/proc/cpuinfo")
    if "hypervisor" in cpuinfo or "QEMU" in cpuinfo or "KVM" in cpuinfo or "Virtual" in cpuinfo:
      detected = true
      info.add("Hypervisor flags found in /proc/cpuinfo")
  
  if dirExists("/sys/hypervisor"):
    detected = true
    info.add("/sys/hypervisor directory exists")
  
  if fileExists("/proc/scsi/scsi"):
    let scsi = readFile("/proc/scsi/scsi")
    if "VBOX" in scsi or "VMware" in scsi:
      detected = true
      info.add("Virtual SCSI devices detected")
  
  details["VMArtifacts"] = %*{"detected": detected, "info": info}
  return detected

proc checkHardwareInconsistency(details: var JsonNode): bool =
  ## Checks for hardware inconsistencies typical in sandboxes (e.g., low resources).
  var detected = false
  var info: seq[string] = @[]
  
  # Check memory (expect at least 256MB for real IoT, sandboxes might be lower)
  if fileExists("/proc/meminfo"):
    let meminfo = readFile("/proc/meminfo")
    for line in meminfo.splitLines():
      if line.startsWith("MemTotal:"):
        let memKB = line.splitWhitespace()[1].parseInt()
        if memKB < 256 * 1024:  # Less than 256MB
          detected = true
          info.add("Low memory detected: " & $memKB & " KB")
        break
  
  # Check disk size (expect at least 1GB)
  let (dfOutput, _) = execCmdEx("df /")
  for line in dfOutput.splitLines():
    if "/" in line:
      let parts = line.splitWhitespace()
      if parts.len > 3:
        let sizeGB = parts[1].parseInt() / (1024 * 1024)  # Convert KB to GB approx
        if sizeGB < 1:
          detected = true
          info.add("Low disk size detected: " & $sizeGB & " GB")
  
  details["HardwareInconsistency"] = %*{"detected": detected, "info": info}
  return detected

proc checkTimingAnalysis(details: var JsonNode): bool =
  ## Performs timing analysis to detect emulation overhead.
  var detected = false
  var info: seq[string] = @[]
  
  let start = cpuTime()
  var sum = 0.0
  for i in 0 ..< 1_000_000:
    sum += sin(float(i))
  let elapsed = cpuTime() - start
  
  # Arbitrary threshold: if > 0.5s, suspect emulation (calibrate based on device)
  if elapsed > 0.5:
    detected = true
    info.add("Timing anomaly: loop took " & $elapsed & " seconds")
  
  details["TimingAnalysis"] = %*{"detected": detected, "info": info}
  return detected

proc checkProcessAnalysis(details: var JsonNode): bool =
  ## Checks for common analysis processes.
  var detected = false
  var info: seq[string] = @[]
  
  let (psOutput, _) = execCmdEx("ps aux")
  let suspicious = ["strace", "gdb", "tcpdump", "wireshark", "valgrind"]
  for procName in suspicious:
    if procName in psOutput:
      detected = true
      info.add("Suspicious process found: " & procName)
  
  details["ProcessAnalysis"] = %*{"detected": detected, "info": info}
  return detected

proc checkRegistryAnalysis(details: var JsonNode): bool =
  ## Adapted for IoT: checks for analysis-related files or configs instead of registry.
  var detected = false
  var info: seq[string] = @[]
  
  let suspiciousFiles = ["/etc/wireshark", "/usr/bin/strace", "/usr/bin/gdb"]
  for f in suspiciousFiles:
    if fileExists(f) or dirExists(f):
      detected = true
      info.add("Analysis tool found: " & f)
  
  details["RegistryAnalysis"] = %*{"detected": detected, "info": info}
  return detected

proc checkUserActivity(details: var JsonNode): bool =
  ## Checks for user activity (e.g., uptime, logged users).
  var detected = false
  var info: seq[string] = @[]
  
  # Low uptime might indicate fresh sandbox
  if fileExists("/proc/uptime"):
    let uptimeStr = readFile("/proc/uptime").split()[0]
    let uptime = uptimeStr.parseFloat()
    if uptime < 3600:  # Less than 1 hour
      detected = true
      info.add("Low uptime: " & $uptime & " seconds")
  
  # No logged users (who command)
  let (whoOutput, _) = execCmdEx("who")
  if whoOutput.strip() == "":
    detected = true
    info.add("No logged-in users")
  
  details["UserActivity"] = %*{"detected": detected, "info": info}
  return detected

proc checkNetworkFingerprint(details: var JsonNode): bool {.async.} =
  ## Checks network for sandbox indicators (e.g., virtual interfaces).
  var detected = false
  var info: seq[string] = @[]
  
  let (ifconfigOutput, _) = execCmdEx("ifconfig")  # or ip link
  if "Virtual" in ifconfigOutput or "veth" in ifconfigOutput or "tap" in ifconfigOutput:
    detected = true
    info.add("Virtual network interface detected")
  
  # Optional: check external IP or connectivity (async)
  try:
    let client = newAsyncHttpClient()
    let response = await client.get("https://api.ipify.org")
    let ip = await response.body
    # If IP is in known analysis ranges (e.g., cloud providers), but skip for simplicity
    info.add("External IP: " & ip)
  except:
    info.add("Network check failed")
  
  details["NetworkFingerprint"] = %*{"detected": detected, "info": info}
  return detected

proc checkMouseMovement(details: var JsonNode): bool =
  ## Stub for IoT: no mouse typically, always false.
  details["MouseMovement"] = %*{"detected": false, "info": ["No mouse support in IoT"]}
  return false

proc checkScreenshotAnalysis(details: var JsonNode): bool =
  ## Stub for IoT: no screen typically, always false.
  details["ScreenshotAnalysis"] = %*{"detected": false, "info": ["No screen support in IoT"]}
  return false

proc isRunningInSandbox*(thoroughCheck: bool = false): Future[SandboxDetectionResult] {.async, raises: [].} =
  var res = SandboxDetectionResult(
    isSandbox: false,
    confidence: 0.0,
    detectedMethods: @[],
    details: %*({}),
    recommendedAction: "Proceed normally"
  )
  
  let methods = [
    (VMArtifacts, checkVMArtifacts),
    (HardwareInconsistency, checkHardwareInconsistency),
    (TimingAnalysis, checkTimingAnalysis),
    (ProcessAnalysis, checkProcessAnalysis),
    (RegistryAnalysis, checkRegistryAnalysis),
    (UserActivity, checkUserActivity),
    # Network is async, handle separately
    (MouseMovement, checkMouseMovement),
    (ScreenshotAnalysis, checkScreenshotAnalysis)
  ]
  
  for (method, check) in methods:
    let detected = check(res.details)
    if detected:
      res.detectedMethods.add(method)
      res.confidence += 0.125  # Equal weight, 8 methods
  
  # Async checks
  let networkDetected = await checkNetworkFingerprint(res.details)
  if networkDetected:
    res.detectedMethods.add(NetworkFingerprint)
    res.confidence += 0.125
  
  if not thoroughCheck:
    # Skip some heavy checks if not thorough, but here all are included; adjust as needed
    discard
  
  res.confidence = min(1.0, res.confidence)
  if res.confidence > 0.5:
    res.isSandbox = true
    res.recommendedAction = "Halt operations and evade"
  
  return res
