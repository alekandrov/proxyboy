# Proxyboy

Proxy de debugging HTTP/HTTPS multiplataforma (macOS, Windows y Linux), inspirado en Proxyman.
Hecho con **Electron + Node.js**, sin servicios externos: todo corre en tu máquina.

## Funcionalidades

- **Captura HTTP y HTTPS** (MITM con CA local generada en tu equipo).
- **SSL Proxying por dominio** con comodines (`*.uala.com.ar`) o para todo; el resto pasa como túnel sin descifrar.
- **Inspector** de request/response lado a lado: headers, query, body (Pretty JSON / Raw / Hex / imágenes), cookies, raw y timing. Descomprime gzip, deflate, br y zstd.
- **Sidebar de dominios**, fijados, filtros por tipo (JSON, imágenes, errores…) y búsqueda (`-texto` excluye).
- **Repetir** y **Editar y repetir** (doble clic), **Nuevo request** (⌘/Ctrl+N).
- **Copiar como cURL**, copiar URL/body, **exportar HAR**.
- **Map Local**: mockeá respuestas (status, headers, body) por método + URL con comodines. Se puede crear desde un request capturado.
- **Block List**: corta conexiones a URLs que coincidan.
- **Proxy del sistema** con un clic (se desactiva solo al salir).
- **Instalación del certificado** en el sistema (macOS llavero / Windows almacén del usuario) y página `http://proxy.boy` para bajarlo desde el celular.
- WebSockets (se reenvían y registran; los frames no se decodifican aún).
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

Levanta servidores HTTP/HTTPS locales y verifica captura, HTTPS interceptado, túnel, gzip, Map Local, repetir y HAR.

## Estructura

| Archivo | Qué hace |
|---|---|
| `src/main/proxy.js` | Motor del proxy (HTTP, CONNECT/MITM, WebSocket, reglas, HAR) |
| `src/main/ca.js` | CA raíz y certificados por host (node-forge) |
| `src/main/system.js` | Proxy del sistema y confianza del certificado por SO |
| `src/main/main.js` | Proceso principal de Electron e IPC |
| `src/renderer/*` | UI (HTML/CSS/JS sin frameworks, tabla virtualizada) |

Los datos (CA, configuración) se guardan en la carpeta de datos de la app (`~/Library/Application Support/proxyboy` en macOS, `%APPDATA%\proxyboy` en Windows). La clave privada de la CA nunca sale de tu equipo: no la compartas.

## Pendiente / ideas
- Breakpoints (pausar y editar request/response en vivo)
- Map Remote, Scripting
- HTTP/2 hacia el cliente, frames de WebSocket, gRPC/Protobuf
- Comparar requests (diff)
