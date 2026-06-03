# LAN Transfer CLI 🚀

Una herramienta de línea de comandos ultrarrápida y extremadamente sencilla para transferir archivos directamente entre computadoras en tu red local (LAN) mediante conexión P2P (Peer-to-Peer).

Olvídate de configurar puertos SSH, levantar servidores FTP o usar cables USB. Con un solo comando expones el archivo, y con otro lo descargas.

## Características ✨
- **P2P Directo:** Transferencia a máxima velocidad aprovechando tu red LAN local.
- **Sin Instalaciones Complejas:** Sólo requiere Python. No hay configuraciones previas ni bases de datos.
- **Seguridad "Un solo uso":** Al terminar la descarga de forma exitosa, el mini-servidor se apaga automáticamente, evitando que quede expuesto de forma permanente.
- **Interfaz Hermosa:** Desarrollado usando `rich` para paneles informativos y `tqdm` para una barra de progreso precisa que muestra MB/s y tiempo restante.
- **Cancelación Segura:** Permite interrumpir la transferencia limpiamente usando `Ctrl+C`.

## Instalación 🛠️

1. Clona o descarga este repositorio.
2. Crea un entorno virtual (opcional pero recomendado):
   ```bash
   python -m venv venv
   # En Windows: venv\Scripts\activate
   # En Linux/Mac: source venv/bin/activate
   ```
3. Instala las dependencias necesarias:
   ```bash
   pip install -r requirements.txt
   ```

## Modo de Uso 📖

La aplicación cuenta con dos comandos principales: `send` (Emisor) y `receive` (Receptor). Puedes utilizar `lan-transfer --help` en cualquier momento para ver la documentación interna.

### 1. Enviar un archivo (Modo Emisor)
Ejecuta el script en modo `send` apuntando a la ruta del archivo que quieres enviar.

```bash
lan-transfer send "C:\Ruta\Al\Video.mp4"
```
*El programa generará automáticamente un código que te indicará la IP y el comando exacto para descargar.*

### 2. Recibir un archivo (Modo Receptor)
En tu otra computadora, simplemente pega el comando generado por el emisor:

```bash
lan-transfer receive 192.168.1.5:43210 "Video.mp4"
```
*Verás inmediatamente una barra de progreso detallada. Al llegar al 100%, el archivo se guardará en tu directorio actual y el emisor se apagará por completo.*

---
Hecho con ♥️ para las transferencias sin fricción.
