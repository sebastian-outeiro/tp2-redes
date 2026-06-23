# TA-048 Redes - Trabajo Práctico 2: SDN / NAT

## Integrantes

| Nombre            | Padrón |
|-------------------|--------|
|Oswaldo Maldonado  | 110404 |
|Sebastian Outeiro  | 92018 |
|Tomás Bautista Conti | 111760 |
|Federica Mortimer | 108034 |
|Lionel Maydana | 106512 |

## Entorno de Trabajo y Ejecución

### Requisitos

- Python 3
- Mininet
- POX controller

### Instalación de POX

Clonar el repositorio oficial:
https://github.com/noxrepo/pox.git

### Ubicación del controlador

El archivo (`protorouter.py`) debe ubicarse en el directorio `pox/ext/`

### Ejecución del controlador

Desde una terminal, ejecutar:  
`python3 pox/pox.py [log.level --DEBUG] protorouter`

### Ejecución de la topología

En otra terminal, ejecutar:  
`sudo python3 topo.py`

### Orden de ejecución recomendado

- Iniciar el controlador POX.
- Ejecutar la topología en Mininet.
- Verificar que el switch se conecte al controlador.

### Verificación básica

- Iniciar la red.
- Desde la CLI de Mininet:
    - Probar conectividad: `h2 ping h1`

## Prueba Presentación

### Preparación
Modificar, de acuerdo a lo indicado por los docentes, las direcciones IP y/o MAC parametrizadas en los scripts Python.
1. Iniciar el controlador en una terminal:

```
python3 pox.py <controller_file> 
```

2. Ejecutar la topología en otra terminal:

```
sudo python3 topo.py
```

3. Abrir, desde mininet, terminales xterm para el server y clientes:

```
xterm h1 h2 h3
```

El tamaño de font se puede ajustar con Ctrl + Botón Derecho  o lanzándolo con:

```
h1 xterm -fa Monospace -fs 12 &
h2 xterm -fa Monospace -fs 12 &
h3 xterm -fa Monospace -fs 12 &
```

### Prueba con Server y Un Cliente
1. Iniciar Wireshark tanto en el cliente como en el servidor:

```
mininet> h2 wireshark >/dev/null 2>&1 &
mininet> h1 wireshark >/dev/null 2>&1 &
```

2. Correr el server iperf desde la xterm de h1:
```
iperf -s
```

3. Iniciar capturas en ambas instancias de Wireshark.
4. Ejecutar cliente iperf desde la xterm de h2 apuntando a h1
```
iperf -c <ip_h1>
```
Ejemplo:
```
iperf -c 200.0.0.1
```

5. Verificar:
- Que la conexión llegue al server iperf desde la IP pública del NAT.
- La traducción de IP y puerto origen (visibles en las salidas de iperf).
- Los paquetes observados en Wireshark:
  - Intercambio de ARP (requests y replies)
  - IPs, MACs, puertos TCP/UDP, etc..
- La instalación de flujos en el switch:
  - `sudo ovs-ofctl dump-flows s1` en otra terminal de Linux.
- Interpretar el significado de los principales campos de los flujos instalados.


6. Repetir con UDP.

```
iperf -s -u
```

```
iperf -u -c <ip_h1>
```

7. Prueba con Múltiples Clientes
- Ejecutar simultáneamente 2 o 3 clientes iperf desde distintos hosts de la red privada.
- Realizar las pruebas tanto con TCP como con UDP.
- Verificar, mediante las salidas de iperf, la traducción de direcciones IP y puertos para cada conexión.
- Explicar cómo la implementación distingue y mantiene el estado de múltiples conexiones concurrentes.

### Aclaraciones

Explicación de la implementación
- Durante la demo, cualquiera de los integrantes del grupo podrá ser consultado sobre la implementación. Todos deberán poder explicar:
- La resolución dinámica de ARP.
- La estructura de la tabla NAT/PAT utilizada.
- La asignación de puertos públicos.
- La instalación y expiración de flujos OpenFlow.
- Cómo se maneja el envío de paquetes cuando aún no se conoce la dirección MAC de destino.