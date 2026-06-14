# API

Todas as rotas retornam JSON. O papel de demonstração é informado em `X-SOC-Role: analyst|lead|viewer`.

## Endpoints

| Método | Rota | Papel | Descrição |
|---|---|---|---|
| `GET` | `/api/health` | Todos | Health check. |
| `GET` | `/api/summary` | Todos | Métricas, severidade, táticas e tendência. |
| `GET` | `/api/sources` | Todos | Saúde e volume das fontes. |
| `GET` | `/api/events` | Todos | Hunt com `q`, `sourceType`, `category`, `outcome` e `limit`. |
| `POST` | `/api/ingest` | Analista, Líder | Normaliza um lote e executa detecções. |
| `POST` | `/api/simulate` | Analista, Líder | Gera uma sequência de comprometimento de identidade. |
| `GET/PATCH` | `/api/alerts/:id` | Leitura: todos; escrita: Analista, Líder | Evidências e triagem. |
| `GET/POST/PATCH` | `/api/cases/:id` | Leitura: todos; escrita: Analista, Líder | Investigações e timeline. |
| `GET/PATCH` | `/api/rules/:id` | Leitura: todos; escrita: Líder | Configuração das regras. |
| `GET` | `/api/audit` | Todos | Últimas ações auditadas. |

## Ingestão

```json
{
  "source": "identity",
  "events": [
    {
      "timestamp": "2026-06-14T14:30:00.000Z",
      "username": "maria",
      "ip": "203.0.113.15",
      "success": false,
      "application": "vpn-gateway"
    }
  ]
}
```

Fontes aceitas: `identity`, `web`, `endpoint`, `network`, `cloud` e `generic`.

## Evento normalizado

Campos principais: `id`, `timestamp`, `sourceType`, `category`, `action`, `outcome`, `message`, `sourceIp`, `destinationIp`, `destinationPort`, `user`, `host`, `processName`, `commandLine`, `httpMethod`, `httpPath`, `statusCode`, `cloudAction` e `raw`.

## Regras incluídas

| Regra | Tipo | MITRE ATT&CK |
|---|---|---|
| Repeated authentication failures | Correlação | T1110 Brute Force |
| Successful login after repeated failures | Correlação | T1078 Valid Accounts |
| Encoded PowerShell execution | Match | T1059.001 PowerShell |
| Web exploitation pattern | Match | T1190 Exploit Public-Facing Application |
| Scheduled task creation | Match | T1053.005 Scheduled Task |
| Network service discovery | Correlação | T1046 Network Service Discovery |
