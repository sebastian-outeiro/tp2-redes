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
