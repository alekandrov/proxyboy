# Proxyboy

Proxy de debugging HTTP/HTTPS multiplataforma (macOS, Windows y Linux), inspirado en Proxyman.
Hecho con **Electron + Node.js**, sin servicios externos: todo corre en tu máquina.

## Funcionalidades

- **Captura HTTP y HTTPS** (MITM con CA local generada en tu equipo).
- **SSL Proxying por dominio** con comodines (`*.uala.com.ar`) o para todo; el resto pasa como túnel sin descifrar.
- **Inspector** de request/response lado a lado: headers, query, body (Pretty JSON / Raw / Hex / imágenes), cookies, raw y timing. Descomprime gzip, deflate, br y zstd.
- **Apps**: cada request muestra qué app lo hizo, con su ícono (Chrome, Slack, curl…). Las apps del **simulador de iOS** aparecen con su nombre, ícono y dispositivo (ej. "Ualá-Stage · iPhone 17 Pro · iOS 26.2"). Los celulares conectados por Wi-Fi se identifican por User-Agent.
- **Sidebar** con Apps (expandibles por dominio), dominios, fijados, filtros por tipo (JSON, imágenes, errores…) y búsqueda (`-texto` excluye).
- **Repetir** y **Editar y repetir** (doble clic), **Nuevo request** (⌘/Ctrl+N).
- **Copiar como cURL**, copiar URL/body, **exportar HAR**.
- **HTTP/2** hacia el cliente y hacia el servidor (negociado por ALPN), con trailers: funciona con **gRPC**.
- **Vista Protobuf / gRPC sin esquema**: decodifica los mensajes (campos numerados, anidados, repetidos).
- **WebSockets**: se ven los mensajes enviados/recibidos (JSON formateado, binarios en hex).
- **Comparar** dos requests (diff de request y response).
- **Reglas** (⌘/Ctrl+⌥+L), todas con método + URL con comodines:
  - **Map Local**: mockeá respuestas (status, headers, body). Se puede crear desde un request capturado.
  - **Map Remote**: redirigí requests a otro servidor (ej. `https://api.uala.com.ar/*` → `http://localhost:8080`).
  - **Breakpoints**: pausá el request y/o la response para editar método, URL, status, headers y body antes de seguir, o abortar.
  - **Scripts**: JavaScript con `onRequest` / `onResponse` que modifica el tráfico al vuelo; `console.log` aparece en la pestaña Info.
  - **Block List**: corta conexiones a URLs que coincidan.
- **Proxy del sistema** con un clic (se desactiva solo al salir).
- **Instalación del certificado** en el sistema (macOS llavero / Windows almacén del usuario) y página `http://proxy.boy` para bajarlo desde el celular.
- Modo consola sin UI.

## Uso

```bash
npm install
```

```bash
npm start
```

1. Tocá **Certificado → Instalar y confiar** (una sola vez).
2. Tocá **Proxy del sistema**, o configurá tu app/dispositivo con `IP:9090`.
3. En **SSL** agregá los dominios a descifrar (o clic derecho sobre un dominio → *Habilitar SSL Proxying*).

### Celular / simulador
Poné el proxy HTTP del Wi-Fi en `IP-de-tu-compu:9090`, abrí `http://proxy.boy` y descargá el certificado.
- iOS: además activá la confianza en Ajustes → General → Información → Confianza de certificados.
- Android 7+: la app debe confiar en CAs de usuario (`network_security_config`, solo en debug).

### Consola

```bash
npm run proxy -- --port 9090 --ssl "*.uala.com.ar,api.example.com"
```

### Empaquetar

```bash
npm run dist:mac
```

```bash
npm run dist:win
```

## Tests

```bash
npm test
```

Levanta servidores locales (HTTP, HTTPS, HTTP/2 estilo gRPC y WebSocket) y verifica captura, HTTPS interceptado,
HTTP/2 con trailers, túnel, gzip, Map Local, Map Remote, Block, breakpoints, scripts, WebSocket, repetir y HAR.

## Scripts: ejemplo

```js
async function onRequest(context, url, request) {
  request.headers['Authorization'] = 'Bearer token-de-prueba';
  return request;
}

async function onResponse(context, url, request, response) {
  const body = JSON.parse(response.body);
  body.feature_flag = true;
  response.body = body; // los objetos se serializan a JSON
  return response;
}
```

Los scripts corren en un sandbox de Node (`vm`) con timeout de 2 s. No es un aislamiento de seguridad: usá solo scripts propios.

## Estructura

| Archivo | Qué hace |
|---|---|
| `src/main/proxy.js` | Motor del proxy (HTTP/1.1 y HTTP/2, CONNECT/MITM, WebSocket, reglas, breakpoints, HAR) |
| `src/main/upstream.js` | Conexiones al servidor real (HTTP/1.1 y HTTP/2 con ALPN y sesiones reutilizables) |
| `src/main/rules.js` | Matching con comodines, Map Remote y sandbox de scripts |
| `src/main/websocket.js` | Parser de frames WebSocket |
| `src/main/procinfo.js` | Identifica la app de cada conexión (lsof / netstat / ss + bundle, simulador iOS, User-Agent) |
| `src/main/ca.js` | CA raíz y certificados por host (node-forge) |
| `src/main/system.js` | Proxy del sistema y confianza del certificado por SO |
| `src/main/main.js` | Proceso principal de Electron e IPC |
| `src/renderer/*` | UI (HTML/CSS/JS sin frameworks, tabla virtualizada) |

Los datos (CA, configuración) se guardan en la carpeta de datos de la app (`~/Library/Application Support/proxyboy` en macOS, `%APPDATA%\proxyboy` en Windows). La clave privada de la CA nunca sale de tu equipo: no la compartas.

## Limitaciones conocidas
- Los mensajes gRPC comprimidos (`grpc-encoding: gzip`) se muestran sin decodificar.
- WebSocket sobre HTTP/2 (RFC 8441) no se intercepta: los clientes usan HTTP/1.1 para WebSocket.
- Para leer los mensajes WebSocket, Proxyboy quita la compresión `permessage-deflate` del handshake.
- Los requests con breakpoint o script se bufferizan completos (hasta 50 MB).
- Para identificar la app, el primer request de cada conexión local espera hasta 300 ms a que se resuelva el proceso (en la práctica corre en paralelo con el request al servidor).
- Probado en macOS. El código para Windows (proxy del sistema vía registro, certificado vía `certutil`) todavía no se probó en una máquina Windows.
