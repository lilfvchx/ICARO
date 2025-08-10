

# AGENT.md: Diseño de un Agente de Botnet Avanzada para Investigación en Ciberseguridad

**ADVERTENCIA:** Este documento es una simulación teórica para fines de investigación en ciberseguridad. Su objetivo es analizar y comprender las técnicas utilizadas por las botnets modernas para desarrollar contramedidas más efectivas. Todo el contenido aquí presente debe ser tratado como una especulación académica y no debe ser implementado en sistemas reales sin el debido consentimiento y en un entorno de laboratorio controlado. El uso indebido de esta información es estrictamente responsabilidad del usuario.

## 1. Arquitectura del Agente y Máquina de Estados

### 1.1. Diseño de la Máquina de Estados (FSM)

La arquitectura del agente se basa en una Máquina de Estados Finita (FSM) jerárquica, un modelo que permite una gestión clara y eficiente del ciclo de vida del agente en dispositivos con recursos limitados. Este enfoque es particularmente adecuado para sistemas embebidos, ya que facilita la modularidad y la predictibilidad del comportamiento, lo que es crucial para la evasión de detección y la resiliencia. La FSM principal del agente gestionará los estados de alta nivel, mientras que sub-máquinas de estados manejarán tareas más complejas y específicas, como la propagación o la comunicación P2P. La implementación se inspirará en frameworks ligeros como `UML-State-Machine-in-C` , que ha demostrado ser altamente eficiente en términos de consumo de memoria y CPU, requiriendo solo 116 bytes de memoria de código para una FSM simple y 424 bytes para una jerárquica . Esta eficiencia es fundamental para operar de manera encubierta en dispositivos IoT, donde los recursos son escasos y cualquier anomalía en el consumo puede delatar la presencia del agente. La FSM permitirá al agente transicionar entre diferentes modos de operación, como el estado de reposo, el escaneo activo, la fase de explotación y la integración en la red P2P, todo ello de manera controlada y secuencial.

#### 1.1.1. Definición de Estados Principales

La FSM del agente se estructurará en torno a un conjunto de estados principales que definen su comportamiento operacional. Cada estado representa una fase del ciclo de vida del agente, desde su despliegue inicial hasta su integración completa en la botnet. Los estados clave incluyen:

*   **`ESTADO_INICIAL`**: Este es el estado de arranque del agente. Tras la infección, el agente realiza una inicialización básica, verifica su entorno de ejecución para detectar posibles sandboxes o entornos de análisis, y establece los recursos necesarios para su operación. En este estado, el agente es altamente cauteloso y minimiza su actividad de red para evitar la detección.
*   **`ESTADO_PERSISTENCIA`**: Una vez inicializado, el agente intenta establecer la persistencia en el dispositivo. Esto puede implicar la modificación de scripts de inicio, la inyección en procesos del sistema o técnicas más avanzadas como la modificación del firmware para sobrevivir a un reinicio de fábrica. El objetivo es asegurar que el agente permanezca activo incluso después de que el dispositivo se reinicie.
*   **`ESTADO_RECONOCIMIENTO`**: En este estado, el agente comienza a explorar su entorno de red. Realiza un escaneo de la red local para identificar otros dispositivos potencialmente vulnerables. Este reconocimiento es la base para la fase de propagación y se realiza de manera sigilosa para no levantar sospechas.
*   **`ESTADO_PROPAGACION`**: Tras identificar objetivos, el agente entra en el estado de propagación. Aquí, intenta infectar a los nuevos dispositivos utilizando una combinación de ataques de fuerza bruta y la explotación de vulnerabilidades conocidas (CVEs). Este estado es altamente activo y representa la fase de crecimiento de la botnet.
*   **`ESTADO_COMUNICACION_P2P`**: Una vez establecida la persistencia y completada la fase de propagación inicial, el agente se integra en la red P2P de la botnet. En este estado, se comunica con otros peers para recibir comandos, descargar nuevos módulos o plugins, y reportar información. La comunicación es descentralizada, lo que aumenta la resiliencia de la botnet.
*   **`ESTADO_EJECUCION_PAYLOAD`**: Este estado se activa cuando el agente recibe un comando para ejecutar una acción específica, como lanzar un ataque DDoS, robar datos o realizar una exploración más profunda de la red. El agente descarga el payload correspondiente desde la red P2P y lo ejecuta de manera nativa para maximizar la eficiencia.

#### 1.1.2. Transiciones y Eventos

Las transiciones entre los estados de la FSM serán disparadas por eventos específicos, que pueden ser internos (como la finalización de una tarea) o externos (como la recepción de un comando de un peer). La lógica de transición garantizará que el agente responda de manera adecuada a las condiciones cambiantes del entorno. Algunos ejemplos de eventos y sus transiciones correspondientes son:

| Estado Origen | Evento | Estado Destino | Descripción de la Transición |
| :--- | :--- | :--- | :--- |
| `ESTADO_INICIAL` | `EVENTO_INFECCION_INICIAL` | `ESTADO_PERSISTENCIA` | El agente ha completado las verificaciones iniciales y está listo para establecer persistencia. |
| `ESTADO_PERSISTENCIA` | `EVENTO_PERSISTENCIA_EXITOSA` | `ESTADO_RECONOCIMIENTO` | La persistencia ha sido establecida, el agente comienza a explorar la red. |
| `ESTADO_RECONOCIMIENTO` | `EVENTO_OBJETIVO_ENCONTRADO` | `ESTADO_PROPAGACION` | Se ha identificado un dispositivo vulnerable, se inicia el intento de infección. |
| `ESTADO_PROPAGACION` | `EVENTO_INFECCION_EXITOSA` | `ESTADO_RECONOCIMIENTO` | La infección fue exitosa, el agente vuelve a buscar más objetivos. |
| `ESTADO_COMUNICACION_P2P` | `EVENTO_COMANDO_RECIBIDO` | `ESTADO_EJECUCION_PAYLOAD` | Se ha recibido un comando, se procede a ejecutar la tarea asignada. |
| `ESTADO_EJECUCION_PAYLOAD` | `EVENTO_PAYLOAD_FINALIZADO` | `ESTADO_COMUNICACION_P2P` | La tarea ha finalizado, el agente vuelve a escuchar comandos. |
| `*` | `EVENTO_ERROR_CRITICO` | `ESTADO_ERROR` | Ha ocurrido un error grave (e.g., detección de sandbox), se activa el modo de error. |

#### 1.1.3. Implementación en Rust con `match`

La implementación de la FSM en Rust se beneficiará de las características del lenguaje, como el patrón `match`, que permite una definición clara y concisa de las transiciones de estado. A continuación, se presenta un ejemplo de cómo podría estructurarse la lógica principal de la FSM en Rust:

```rust
// Definición de los estados principales
#[derive(Debug, Clone, Copy)]
enum EstadoAgente {
    Inicial,
    Persistencia,
    Reconocimiento,
    Propagacion,
    ComunicacionP2P,
    EjecucionPayload,
    Error,
}

// Definición de los eventos que causan transiciones
#[derive(Debug)]
enum EventoAgente {
    InfeccionInicial,
    PersistenciaExitosa,
    ObjetivoEncontrado,
    InfeccionExitosa,
    ComandoRecibido(Comando),
    PayloadFinalizado,
    ErrorCritico(String),
}

// Estructura principal del agente
struct Agente {
    estado: EstadoAgente,
    // ... otros campos necesarios para el estado del agente
}

impl Agente {
    fn new() -> Self {
        Agente {
            estado: EstadoAgente::Inicial,
            // ... inicialización de otros campos
        }
    }

    // Función principal que maneja los eventos y las transiciones
    fn manejar_evento(&mut self, evento: EventoAgente) {
        match (self.estado, evento) {
            (EstadoAgente::Inicial, EventoAgente::InfeccionInicial) => {
                println!("Agente inicializado. Transicionando a Persistencia.");
                self.estado = EstadoAgente::Persistencia;
                self.ejecutar_persistencia();
            }
            (EstadoAgente::Persistencia, EventoAgente::PersistenciaExitosa) => {
                println!("Persistencia establecida. Transicionando a Reconocimiento.");
                self.estado = EstadoAgente::Reconocimiento;
                self.ejecutar_reconocimiento();
            }
            (EstadoAgente::Reconocimiento, EventoAgente::ObjetivoEncontrado) => {
                println!("Objetivo encontrado. Transicionando a Propagacion.");
                self.estado = EstadoAgente::Propagacion;
                self.ejecutar_propagacion();
            }
            (EstadoAgente::Propagacion, EventoAgente::InfeccionExitosa) => {
                println!("Propagacion exitosa. Transicionando a Comunicacion P2P.");
                self.estado = EstadoAgente::ComunicacionP2P;
                self.integrar_p2p();
            }
            (EstadoAgente::ComunicacionP2P, EventoAgente::ComandoRecibido(cmd)) => {
                println!("Comando recibido: {:?}. Transicionando a EjecucionPayload.", cmd);
                self.estado = EstadoAgente::EjecucionPayload;
                self.ejecutar_payload(cmd);
            }
            (EstadoAgente::EjecucionPayload, EventoAgente::PayloadFinalizado) => {
                println!("Payload finalizado. Volviendo a Comunicacion P2P.");
                self.estado = EstadoAgente::ComunicacionP2P;
            }
            (_, EventoAgente::ErrorCritico(msg)) => {
                eprintln!("Error critico: {}. Transicionando a estado de Error.", msg);
                self.estado = EstadoAgente::Error;
                self.manejar_error();
            }
            _ => {
                // Transición no válida, se ignora o se maneja según la lógica del agente
                println!("Transición no válida desde {:?} con evento {:?}", self.estado, evento);
            }
        }
    }

    // Métodos auxiliares para las acciones de cada estado
    fn ejecutar_persistencia(&mut self) {
        // Lógica para establecer persistencia
        // ...
        // Simulación de éxito
        self.manejar_evento(EventoAgente::PersistenciaExitosa);
    }

    fn ejecutar_reconocimiento(&mut self) {
        // Lógica para escanear la red
        // ...
        // Simulación de encontrar un objetivo
        self.manejar_evento(EventoAgente::ObjetivoEncontrado);
    }

    fn ejecutar_propagacion(&mut self) {
        // Lógica para intentar la infección
        // ...
        // Simulación de éxito
        self.manejar_evento(EventoAgente::InfeccionExitosa);
    }

    fn integrar_p2p(&mut self) {
        // Lógica para unirse a la red P2P
        println!("Agente integrado en la red P2P, esperando comandos.");
    }

    fn ejecutar_payload(&mut self, cmd: Comando) {
        // Lógica para descargar y ejecutar el payload
        println!("Ejecutando payload para el comando: {:?}", cmd);
        // Simulación de finalización
        self.manejar_evento(EventoAgente::PayloadFinalizado);
    }

    fn manejar_error(&mut self) {
        // Lógica para limpiar y salir
        println!("Agente en estado de error. Saliendo.");
    }
}

// Ejemplo de uso
fn main() {
    let mut agente = Agente::new();
    agente.manejar_evento(EventoAgente::InfeccionInicial);

    // Simulación de recepción de un comando
    // En un escenario real, esto vendría de la red P2P
    // agente.manejar_evento(EventoAgente::ComandoRecibido(Comando::DDoS));
}
```

### 1.2. Estructura del Agente

El agente se estructurará en varios módulos independientes pero interconectados, cada uno responsable de una función específica. Esta arquitectura modular no solo mejora la mantenibilidad del código, sino que también permite una mayor flexibilidad, ya que los módulos pueden ser actualizados o reemplazados de forma individual a través de la red P2P. La comunicación entre módulos se realizará principalmente a través de la FSM principal, que actuará como un orquestador, desencadenando las acciones de cada módulo según el estado actual del agente.

#### 1.2.1. Módulo de Inicialización y Bootstrap

Este es el primer módulo que se ejecuta cuando el agente se despliega en un nuevo dispositivo. Sus responsabilidades incluyen:

*   **Verificación del Entorno**: Detectar si el agente se está ejecutando en un entorno de análisis (sandbox, máquina virtual, etc.). Esto puede incluir la verificación de indicadores como la presencia de ciertos procesos, archivos o registros del sistema, así como la medición de tiempos de respuesta anómalos.
*   **Desofuscación y Desencriptación**: Si el agente se distribuye de forma ofuscada o encriptada, este módulo se encargará de descifrar el código principal y prepararlo para su ejecución.
*   **Resolución de Dependencias**: Verificar la presencia de bibliotecas o herramientas del sistema necesarias para el funcionamiento del agente (por ejemplo, `wget`, `curl`, etc.) y, si no están presentes, buscar alternativas o intentar descargarlas.
*   **Establecimiento de la Configuración Inicial**: Cargar la configuración básica del agente, como las direcciones de los nodos semilla de la red P2P, los puertos a escanear, etc.

#### 1.2.2. Módulo de Comunicación P2P

Este módulo es el encargado de gestionar toda la comunicación con la red de bots. Sus funciones principales son:

*   **Gestión de la Red P2P**: Implementar el protocolo DHT para unirse a la red, mantener una lista de peers activos y propagar información a través de la red.
*   **Envío y Recepción de Comandos**: Codificar y decodificar los mensajes que se intercambian con otros peers, asegurando la integridad y autenticidad de los comandos recibidos.
*   **Descarga de Payloads**: Gestionar la descarga de nuevos módulos o plugins desde otros peers de la red. Esto incluye la verificación de la firma digital de los payloads (si se implementa) para asegurar que provienen de una fuente confiable.
*   **Mecanismos de Fallback**: Implementar mecanismos de comunicación alternativos, como la comunicación a través de un servidor C&C centralizado (como fallback) o el uso de túneles encubiertos (DNS, RTSP), en caso de que la red P2P principal esté comprometida o no sea accesible.

#### 1.2.3. Módulo de Propagación y Exploits

Este es el módulo encargado de la expansión de la botnet. Sus tareas incluyen:

*   **Escaneo de Redes**: Implementar algoritmos de escaneo eficientes para descubrir dispositivos en la red local y en redes remotas (WAN). El escaneo puede ser aleatorio, dirigido o basado en una lista de objetivos predefinida.
*   **Gestión de Vulnerabilidades**: Mantener una base de datos actualizada de vulnerabilidades conocidas (CVEs) y sus correspondientes exploits. Este módulo debe ser capaz de identificar la versión del firmware o del software en el dispositivo objetivo y seleccionar el exploit adecuado.
*   **Motor de Exploits**: Implementar un motor que pueda ejecutar los exploits de forma dinámica. Esto podría incluir la integración de un intérprete de scripts (como Lua) para permitir la ejecución de exploits más complejos y flexibles, similar a lo que hace la botnet Reaper.
*   **Ataques de Fuerza Bruta**: Realizar ataques de fuerza bruta contra servicios como Telnet y SSH, utilizando listas de contraseñas comunes y diccionarios específicos para dispositivos IoT.

#### 1.2.4. Módulo de Persistencia

La supervivencia a largo plazo del agente depende de su capacidad para mantenerse en el dispositivo infectado. Este módulo se encarga de:

*   **Persistencia en el Sistema de Archivos**: Modificar scripts de inicio (`rc.local`, `init.d`, etc.) para asegurar que el agente se ejecute cada vez que el dispositivo se reinicie.
*   **Persistencia en Procesos**: Inyectar el código del agente en procesos del sistema que se ejecutan con privilegios elevados y que son esenciales para el funcionamiento del dispositivo (por ejemplo, `netd`, `dnsmasq`). Esto hace que el agente sea más difícil de detectar y eliminar.
*   **Persistencia en el Firmware**: Implementar técnicas avanzadas para sobrevivir a un reinicio de fábrica. Esto puede incluir la modificación de la partición del bootloader o la inyección del agente en una partición del firmware que no se vea afectada por el reinicio.
*   **Anti-Detección y Anti-Eliminación**: Implementar mecanismos para evitar la detección por parte de herramientas de seguridad y para resistir los intentos de eliminación. Esto puede incluir el ocultamiento de procesos y archivos, así como la monitorización de los procesos del agente para reiniciarlos si son terminados.

#### 1.2.5. Módulo de Defensa y Evasión

Este módulo es crucial para la longevidad de la botnet. Su objetivo es evitar la detección y el análisis por parte de investigadores de seguridad. Sus funciones incluyen:

*   **Detección de Entornos de Análisis**: Implementar una serie de comprobaciones para detectar si el agente se está ejecutando en un entorno de análisis. Esto puede incluir la verificación de indicadores de hardware (por ejemplo, la ausencia de sensores en una máquina virtual), la medición de tiempos de ejecución (las operaciones en una VM suelen ser más lentas) y la búsqueda de herramientas de análisis en el sistema.
*   **Ofuscación de Código y Datos**: Ofuscar el código del agente para dificultar su análisis estático y dinámico. Esto puede incluir el cifrado de las cadenas de texto, la ofuscación del flujo de control y el uso de nombres de variables y funciones sin sentido.
*   **Ofuscación de la Comunicación de Red**: Hacer que el tráfico de red del agente se asemeje al tráfico legítimo. Por ejemplo, si el agente se está comunicando desde una cámara IP, su tráfico podría emular el protocolo ONVIF para pasar desapercibido.
*   **Bloqueo de Competidores**: Implementar mecanismos para detectar y neutralizar otras botnets que intenten infectar el mismo dispositivo. Esto puede incluir el bloqueo de puertos utilizados por otras botnets o la terminación de sus procesos, una técnica utilizada por la botnet Hajime.

## 2. Comunicación Resiliente y Segura

### 2.1. Red P2P Descentralizada

La elección de una arquitectura de red P2P descentralizada es fundamental para la resiliencia y la escalabilidad de la botnet. A diferencia de las arquitecturas cliente-servidor tradicionales, donde la eliminación del servidor de comando y control (C&C) resulta en la desarticulación de toda la red, una red P2P no tiene un único punto de fallo. Cada nodo (agente) en la red puede actuar como cliente y servidor, lo que permite que la red se auto-organice y se recupere de la pérdida de nodos individuales. Este diseño, inspirado en botnets como Hajime y Mozi, garantiza que la red pueda mantenerse operativa incluso si una parte significativa de sus nodos es desactivada. La descentralización también dificulta enormemente el rastreo de los operadores, ya que no hay un servidor central que pueda ser identificado y atacado.

#### 2.1.1. Implementación de DHT con `libp2p-kademlia`

Para implementar la red P2P, se utilizará el protocolo Kademlia, una DHT (Distributed Hash Table) que permite a los nodos de una red encontrarse y almacenar y recuperar información de manera eficiente. En el ecosistema de Rust, la biblioteca `libp2p-kad` es la opción más robusta y madura para este propósito. Kademlia organiza los nodos en una estructura de árbol y utiliza una métrica de distancia XOR para determinar la "proximidad" entre los nodos. Esto permite que las búsquedas de información (por ejemplo, para encontrar un nodo que almacene un comando específico) se resuelvan en un número logarítmico de saltos, lo que es muy eficiente incluso en redes de gran tamaño. La implementación con `libp2p-kad` proporcionará las funcionalidades de descubrimiento de peers, enrutamiento de mensajes y almacenamiento distribuido de datos, que son los pilares de la comunicación P2P.

#### 2.1.2. Protocolo de Comunicación Ligero sobre UDP

Dado que los dispositivos IoT objetivo suelen tener recursos de red y procesamiento muy limitados, es crucial que el protocolo de comunicación sea lo más ligero posible. Por esta razón, se optará por utilizar UDP (User Datagram Protocol) como la capa de transporte subyacente. A diferencia de TCP, UDP no establece una conexión previa y no tiene mecanismos de control de flujo o retransmisión, lo que reduce significativamente la sobrecarga de los paquetes y la latencia de comunicación. Aunque UDP no es fiable por sí solo, la capa de aplicación implementará mecanismos de control de errores y retransmisión simplificados para garantizar la entrega de mensajes críticos, como los comandos de ataque. Además, se utilizarán técnicas de "UDP hole punching" para atravesar los NATs y permitir la comunicación directa entre pares, incluso cuando se encuentran en redes privadas.

#### 2.1.3. Serialización de Datos: MessagePack vs. JSON

La serialización es el proceso de convertir estructuras de datos en un formato que pueda ser almacenado o transmitido y luego reconstruido. La elección del formato de serialización tiene un impacto directo en el tamaño del payload, la eficiencia de análisis y la interoperabilidad del agente. Aunque JSON (JavaScript Object Notation) es un formato ampliamente utilizado y legible por humanos, su representación basada en texto y sus metadatos redundantes (como las comillas en los nombres de las claves) lo hacen relativamente verboso. Para un entorno de recursos limitados como el de los dispositivos IoT, donde cada byte cuenta, se propone utilizar **MessagePack** como formato de serialización principal. MessagePack es un formato de serialización binaria que se describe a sí mismo como "JSON pero rápido y pequeño". Al ser binario, es más compacto que JSON, a menudo reduciendo el tamaño del payload en un 50% o más. Por ejemplo, el número entero `123` se representa como 3 bytes en JSON (`"123"`), mientras que en MessagePack solo ocupa 1 byte. Esta eficiencia en el espacio se traduce directamente en un menor consumo de ancho de banda y una menor latencia de red, lo que es crucial para la propagación rápida de comandos y la descarga de payloads.

### 2.2. Cifrado de Comunicaciones

Para garantizar la confidencialidad, integridad y autenticidad de las comunicaciones entre los agentes de la botnet y los nodos de control, se implementará un esquema de cifrado robusto basado en el algoritmo **XChaCha20-Poly1305**. Este esquema de cifrado autenticado con datos asociados (AEAD) es ampliamente considerado como seguro y está diseñado para ser eficiente tanto en software como en hardware, lo que lo hace ideal para dispositivos IoT con recursos limitados. La elección de XChaCha20-Poly1305 sobre otras alternativas como AES-GCM se debe a su mayor resistencia a los ataques de timing y a su rendimiento superior en plataformas que no tienen instrucciones de hardware dedicadas para AES. Además, el uso de un nonce de 192 bits en XChaCha20 reduce significativamente el riesgo de reutilización accidental del nonce, un error común que puede comprometer la seguridad de los sistemas de cifrado. La implementación de este esquema de cifrado es un pilar fundamental para la resiliencia de la botnet, ya que previene que los operadores de seguridad puedan interceptar y descifrar los comandos y los datos que se intercambian, lo que dificulta enormemente los esfuerzos por desmantelar la infraestructura de la botnet.

#### 2.2.1. Implementación de XChaCha20-Poly1305

La implementación de XChaCha20-Poly1305 se realizará utilizando bibliotecas criptográficas bien establecidas y auditadas, como `libsodium` o sus equivalentes en Rust, como el crate `orion` o `chacha20poly1305`. Estas bibliotecas proporcionan una API de alto nivel que abstrae la complejidad de la implementación criptográfica y garantiza que el cifrado se utilice de manera segura. El esquema AEAD proporciona tanto confidencialidad (mediante el cifrado XChaCha20) como autenticación e integridad (mediante el código de autenticación de mensajes Poly1305). Esto significa que, además de mantener los datos en secreto, el receptor puede verificar que el mensaje no ha sido modificado y que proviene de una fuente auténtica. La clave para el cifrado se puede derivar de un secreto compartido entre los agentes y los operadores, o se puede utilizar un sistema de intercambio de claves como el protocolo de acuerdo de claves de Diffie-Hellman (DH) o su versión de curva elíptica (ECDH) para establecer claves de sesión seguras.

#### 2.2.2. Gestión de Claves y Autenticación

La gestión segura de las claves criptográficas es tan importante como el algoritmo de cifrado en sí. El agente necesitará una forma de obtener y almacenar las claves necesarias para la comunicación. Una posible implementación es la derivación de claves a partir de una "semilla" o "contraseña maestra" que esté codificada en el binario del agente. Sin embargo, este enfoque es vulnerable si el binario es analizado y la semilla es extraída. Un enfoque más robusto sería la utilización de un sistema de intercambio de claves de curva elíptica (ECDH) para generar claves de sesión únicas para cada comunicación. En este esquema, cada agente tendría un par de claves pública y privada. Al iniciar una comunicación, los agentes intercambian sus claves públicas y utilizan su propia clave privada y la clave pública del otro para derivar una clave de sesión compartida. Esta clave de sesión se utilizaría luego para el cifrado XChaCha20-Poly1305. Este método garantiza que incluso si una clave de sesión es comprometida, las comunicaciones pasadas y futuras no lo estarán.

#### 2.2.3. Ejemplo de Cifrado/Descifrado de Archivos en Rust

A continuación, se muestra un ejemplo de cómo se podría implementar el cifrado y descifrado de datos utilizando el crate `chacha20poly1305` en Rust. Este ejemplo ilustra el uso de la función `encrypt` y `decrypt` para proteger un mensaje.

```rust
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generar una clave aleatoria (32 bytes para XChaCha20Poly1305)
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(&key);

    // Generar un nonce aleatorio (24 bytes para XChaCha20Poly1305)
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let plaintext = b"Este es un mensaje secreto de la botnet";

    // Cifrar el mensaje
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
        .expect("Error al cifrar el mensaje");
    println!("Texto cifrado: {:?}", ciphertext);

    // Descifrar el mensaje
    let decrypted_plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())
        .expect("Error al descifrar el mensaje");
    println!("Texto descifrado: {:?}", String::from_utf8(decrypted_plaintext).unwrap());

    Ok(())
}
```

### 2.3. Mecanismos de Fallback

A pesar de la resiliencia de una red P2P, es posible que en algunos entornos la comunicación P2P esté bloqueada o que la red se vea comprometida. Para garantizar que los operadores puedan mantener el control de la botnet incluso en estas situaciones adversas, el agente implementará mecanismos de fallback. Estos mecanismos proporcionan canales de comunicación alternativos que se activan automáticamente cuando la comunicación P2P principal falla.

#### 2.3.1. Comunicación Híbrida HTTP/P2P

El mecanismo de fallback principal será la comunicación a través de HTTP/HTTPS con un servidor de comando y control (C&C) tradicional. El agente estará diseñado con una arquitectura de comunicación híbrida. Intentará conectarse a la red P2P como su método preferido, pero si después de un período de tiempo determinado no puede establecer una conexión o si la conexión se pierde y no puede ser restablecida, activará automáticamente el modo de fallback HTTP. En este modo, el agente contactará con un servidor C&C predefinido (cuya dirección puede estar codificada en el binario o descargarse de una ubicación estática) para recibir comandos y actualizaciones. Este enfoque híbrido combina la resiliencia de la red P2P con la fiabilidad de un canal de comunicación centralizado, asegurando que la botnet pueda ser controlada en cualquier circunstancia.

#### 2.3.2. Túneles Encubiertos (DNS, RTSP)

Para una mayor sofisticación y evasión, el agente puede utilizar túneles encubiertos para sus comunicaciones de fallback. Un túnel DNS, por ejemplo, permite exfiltrar datos o recibir comandos a través de consultas y respuestas DNS, que a menudo pasan desapercibidas para los firewalls. El agente codificaría los datos en subdominios de una zona DNS controlada por el atacante. De manera similar, el agente podría utilizar el protocolo RTSP (Real Time Streaming Protocol), que es común en dispositivos de videovigilancia, para ocultar sus comunicaciones. Al emular el tráfico de transmisión de video, el agente puede hacer que sus datos parezcan ser un flujo de video legítimo, lo que dificulta enormemente su detección. Estas técnicas de túneles encubiertos proporcionan canales de comunicación extremadamente sigilosos que pueden ser utilizados como un último recurso cuando todos los demás métodos de comunicación están bloqueados.

## 3. Mecanismos de Propagación y Autoreplicación

### 3.1. Estrategia de Infección Híbrida

La estrategia de infección del agente se basa en un enfoque híbrido que combina múltiples vectores de ataque para maximizar la tasa de propagación y la probabilidad de éxito en diferentes entornos de red. Este diseño se inspira en las botnets más exitosas, como Mirai, que utilizó ataques de fuerza bruta masivos, y Satori o Reaper, que incorporaron la explotación de vulnerabilidades conocidas. El agente no se limitará a un único método, sino que empleará una secuencia lógica y adaptativa de técnicas. Inicialmente, se centrará en el reconocimiento del entorno para identificar objetivos potenciales y sus puntos débiles. Posteriormente, ejecutará ataques de fuerza bruta contra servicios de administración comunes (como Telnet y SSH) y, de forma paralela o secuencial, intentará explotar vulnerabilidades específicas (CVEs) en servicios expuestos. Esta combinación asegura que el agente pueda comprometer dispositivos con contraseñas débiles, así como aquellos que, aunque tengan contraseñas seguras, presenten fallos de seguridad no parcheados en su software. La modularidad del agente permitirá la actualización dinámica de la lista de CVEs y diccionarios de contraseñas, lo que garantiza su efectividad a largo plazo frente a la evolución del panorama de amenazas y la aparición de nuevas vulnerabilidades.

#### 3.1.1. Escaneo de Puertos y Servicios

El primer paso en la fase de propagación es el reconocimiento activo de la red, que consiste en el escaneo de puertos y la identificación de servicios en los dispositivos objetivo. Para ello, el agente implementará un módulo de escaneo eficiente y configurable, inspirado en la funcionalidad de herramientas como `nmap` . Este módulo no será una implementación completa de `nmap`, debido a las limitaciones de recursos en dispositivos embebidos, pero adoptará sus principios fundamentales. El agente podrá realizar escaneos de host discovery para determinar qué dispositivos están activos en la red local o en rangos de IP WAN específicos. Para ello, utilizará técnicas como el escaneo ARP en redes locales (`-PR`) o envío de paquetes ICMP Echo Request (ping), aunque este último puede ser menos efectivo debido a su filtrado frecuente . Una vez identificados los hosts activos, el agente procederá al escaneo de puertos. Se enfocará en un conjunto de puertos de alto valor para dispositivos IoT, como el **21 (FTP), 22 (SSH), 23 (Telnet), 53 (DNS), 80 (HTTP), 443 (HTTPS), 554 (RTSP), 1900 (SSDP), 2323 (Telnet alternativo), 37215 (explotado por Satori), y 52869 (explotado por Satori)** . El agente podrá realizar escaneos TCP SYN (`-sS`), que son más rápidos y sigilosos, o TCP Connect (`-sT`) si no dispone de privilegios elevados . Además, se implementará la detección de versiones de servicios (`-sV`), que intentará determinar el software y su versión exacta en los puertos abiertos. Esta información es crucial para seleccionar el exploit adecuado de la base de datos interna del agente. Por ejemplo, si el agente detecta un banner de `Server: Grandstream HT801`, podrá consultar su base de datos para ver si existen CVEs asociados a esa versión específica de firmware.

#### 3.1.2. Ataques de Fuerza Bruta (Telnet/SSH)

Tras identificar servicios de administración como Telnet (puerto 23) y SSH (puerto 22), el agente procederá a intentar comprometerlos mediante ataques de fuerza bruta, una técnica que fue la piedra angular de la propagación de la botnet Mirai. El agente almacenará internamente un diccionario de credenciales predeterminadas comúnmente encontradas en dispositivos IoT. Este diccionario será dinámico y podrá ser actualizado por los operadores de la botnet a través de la red P2P. Las credenciales incluirán combinaciones de usuarios y contraseñas como `admin:admin`, `root:12345`, `user:user`, y otras específicas de fabricantes. El módulo de fuerza bruta estará diseñado para ser eficiente y no ser demasiado agresivo, evitando así el bloqueo de cuentas o la detección por sistemas de prevención de intrusión (IPS). Para ello, implementará pequeñas pausas entre los intentos de inicio de sesión y podrá variar el orden de las credenciales probadas. Si el agente tiene éxito y obtiene acceso, ejecutará un script de inicialización que descargará y ejecutará el payload principal del agente en el dispositivo recién infectado, estableciendo así un nuevo nodo en la botnet. La eficacia de este método radica en la persistencia de las contraseñas predeterminadas en una gran cantidad de dispositivos IoT, ya que muchos usuarios no las cambian tras la instalación.

#### 3.1.3. Explotación de Vulnerabilidades (CVEs)

En paralelo o como alternativa a la fuerza bruta, el agente empleará la explotación de vulnerabilidades conocidas (CVEs) para lograr la ejecución remota de código (RCE). Esta capacidad, inspirada en botnets como Reaper y Satori, permite al agente comprometer dispositivos incluso si tienen contraseñas seguras. El agente mantendrá una base de datos interna de exploits, que podrá ser actualizada de forma dinámica. Cada exploit estará diseñado para ser ligero y eficiente, adaptado a las limitaciones de recursos de los dispositivos embebidos. La selección del exploit a utilizar se basará en la información recopilada durante la fase de escaneo de servicios. Por ejemplo, si el agente detecta un servicio web en un dispositivo que es conocido por ser vulnerable a un CVE específico (por ejemplo, un RCE en la interfaz de administración web de un router), el agente ejecutará el exploit correspondiente. La ejecución del exploit puede ser tan simple como enviar una solicitud HTTP maliciosa o tan compleja como establecer una cadena de explotación que abuse de múltiples vulnerabilidades. Al igual que con la fuerza bruta, el éxito de la explotación resultará en la descarga y ejecución del payload principal del agente, asegurando la persistencia y la integración del dispositivo en la botnet. La capacidad de explotar CVEs es fundamental para la propagación a gran escala y la supervivencia a largo plazo de la botnet.

### 3.2. Propagación Worm-like

La propagación worm-like es una característica clave que permite a la botnet expandirse de manera autónoma y rápida, sin intervención manual. Este comportamiento, inspirado en la botnet Satori, se basa en la capacidad del agente para escanear activamente su entorno, identificar nuevos objetivos vulnerables y replicarse en ellos. El agente, una vez infectado un dispositivo, no se quedará inactivo; activará su módulo de propagación para buscar y comprometer nuevos dispositivos en la red local y, potencialmente, en redes externas a través de Internet. Este proceso de autoreplicación crea un efecto de bola de nieve, donde cada dispositivo infectado se convierte en un vector de infección para muchos más. La eficiencia de este mecanismo radica en su capacidad para explotar la confianza inherente en las redes locales, donde los dispositivos suelen tener una conectividad más directa y menos restricciones de firewall. Además, la propagación worm-like se diseñará para ser silenciosa, evitando reinicios o interrupciones notables en el dispositivo víctima, lo que ayuda a mantener la infección oculta al usuario legítimo y prolonga la vida útil del nodo comprometido.

#### 3.2.1. Escaneo de Redes Locales (LAN)

El escaneo de la red local es el vector de propagación más inmediato y eficaz para el agente. Una vez que el agente ha infectado un dispositivo, su primera acción será cartografiar su entorno inmediato. Para ello, determinará la subred a la que pertenece (por ejemplo, `192.168.1.0/24`) y comenzará a escanear todos los hosts dentro de ese rango. Este proceso de "ping sweep" o host discovery puede realizarse mediante técnicas ARP en redes Ethernet, que son muy rápidas y fiables, o mediante paquetes ICMP si ARP no es viable . Una vez identificados los hosts activos, el agente procederá al escaneo de puertos en cada uno de ellos, centrándose en los servicios comúnmente encontrados en dispositivos IoT, como se describió anteriormente. La ventaja de este enfoque es que los dispositivos dentro de la misma LAN suelen tener una conectividad directa, sin la interferencia de firewalls perimetrales, lo que facilita enormemente la explotación. El agente puede, por ejemplo, identificar una cámara IP en la misma red, explotar una vulnerabilidad en su servicio web y, en cuestión de segundos, convertirla en un nuevo nodo de la botnet. Este proceso de escaneo y explotación en la LAN se repetirá de forma cíclica, asegurando que cualquier nuevo dispositivo que se conecte a la red sea evaluado y, si es vulnerable, comprometido.

#### 3.2.2. Escaneo de Redes Amplias (WAN)

Para lograr una expansión global, el agente debe ser capaz de propagarse más allá de la red local y escanear direcciones IP en Internet (WAN). Este tipo de escaneo es más complejo y requiere una estrategia más sofisticada para ser eficiente y evitar la detección. El agente no escaneará la totalidad del espacio de direcciones IPv4, ya que sería ineficiente y fácilmente detectable. En su lugar, empleará técnicas de escaneo inteligente y dirigido. Por ejemplo, puede centrarse en rangos de IP geográficamente cercanos o en rangos asignados a proveedores de servicios de Internet (ISPs) conocidos por tener una gran cantidad de clientes residenciales con dispositivos IoT. Además, el agente puede recibir "seeds" o listas de objetivos de alta probabilidad desde la red P2P, que podrían ser generadas por los operadores de la botnet a partir de datos de escaneos anteriores o de servicios de búsqueda de dispositivos como Shodan. El escaneo WAN también será más lento y cuidadoso, con tasas de envío de paquetes controladas para no levantar sospechas. El agente podría utilizar técnicas de evasión de firewall/IDS, como el envío de paquetes fragmentados o el uso de flags TCP inusuales, aunque estas técnicas aumentan la complejidad y el consumo de recursos . El objetivo es encontrar y comprometer dispositivos directamente conectados a Internet, como routers domésticos o DVRs, que a menudo tienen puertos de administración expuestos.

#### 3.2.3. Infección Silenciosa sin Reinicios

Un aspecto crucial de la propagación worm-like es la infección silenciosa, que permite al agente comprometer un dispositivo sin causar una interrupción de servicio que alerte al usuario. Muchas técnicas de explotación, especialmente las que afectan al kernel o a procesos críticos, pueden provocar inestabilidad o reinicios forzados. El agente se diseñará para evitar este comportamiento. La mayoría de las vulnerabilidades que se explotarán serán de tipo RCE en servicios de usuario, como servidores web o servicios de red personalizados. Al explotar estas vulnerabilidades, el agente inyectará su payload en el espacio de memoria del proceso vulnerable y lo ejecutará como un subproceso o un proceso independiente. Este método no afecta al proceso principal de una manera que cause un fallo. Por ejemplo, al explotar un RCE en el servidor web de un router, el agente puede usar una técnica como `fork` y `exec` para lanzar su propio binario, dejando el servidor web original intacto y funcionando. Esto es fundamental para mantener la persistencia y la capacidad de propagación, ya que un dispositivo que se reinicia constantemente no es un nodo fiable en la botnet. Además, evitar reinicios reduce la probabilidad de que el usuario realice una investigación que pueda llevar a la detección y eliminación del malware.

### 3.3. Ejecución Nativa de Payloads

La capacidad de descargar y ejecutar payloads adicionales de forma nativa es una característica avanzada que otorga a la botnet una flexibilidad y escalabilidad extraordinarias. Inspirada en la arquitectura de botnets como Mozi y Reaper, esta funcionalidad permite a los operadores de la botnet introducir nuevas capacidades, actualizar el agente o lanzar ataques específicos sin necesidad de recompilar y redistribuir el binario principal del agente. El agente base actúa como un "loader" o un "stager" que se encarga de mantener la persistencia, la comunicación P2P y la propagación básica. Los módulos de ataque más complejos, como los motores de DDoS, los exploits para nuevas vulnerabilidades o las herramientas de robo de datos, se entregan como plugins descargables. Estos plugins serán binarios compilados para las arquitecturas objetivo (principalmente ARM y MIPS), lo que garantiza una ejecución eficiente y sin la sobrecarga de un intérprete o sandbox. Este diseño modular no solo reduce el tamaño del agente inicial, sino que también hace que la botnet sea más adaptable y difícil de analizar, ya que su funcionalidad completa solo se revela cuando se descargan y ejecutan los plugins.

#### 3.3.1. Descarga de Plugins desde Peers/C2

El mecanismo de descarga de plugins se integrará en el protocolo de comunicación P2P del agente. Los operadores de la botnet pueden propagar un comando a través de la red DHT que contenga el hash criptográfico del plugin deseado. Los agentes, al recibir este comando, verificarán si ya tienen el plugin en su caché local. Si no es así, iniciarán un proceso de búsqueda y descarga en la red P2P, similar a cómo funciona un cliente de BitTorrent. Buscarán peers que tengan el plugin identificado por su hash y lo descargarán en fragmentos. Una vez que la descarga se complete y se verifique la integridad del archivo mediante su hash, el plugin estará listo para ser ejecutado. Este sistema de distribución descentralizado es muy resiliente, ya que no depende de un único servidor de descarga (C&C) que pueda ser eliminado. Si un peer que almacena el plugin se desconecta, el agente puede buscarlo en otros peers. Además, el uso de hashes criptográficos asegura que los plugins no puedan ser modificados o falsificados por atacantes, garantizando que solo el código autorizado por los operadores de la botnet se ejecute en los dispositivos comprometidos.

#### 3.3.2. Ejecución de Código de Máquina en Memoria

Para maximizar la eficiencia y la sigilo, los plugins no se ejecutarán como archivos en el sistema de archivos del dispositivo, lo que podría ser detectado por un análisis forense. En su lugar, el agente implementará técnicas de ejecución en memoria. Una vez que el plugin se ha descargado y verificado, el agente reservará una región de memoria con permisos de lectura, escritura y ejecución (usando `mmap` o `VirtualAlloc`). Luego, copiará el contenido del binario del plugin en esta región de memoria y transferirá la ejecución a su punto de entrada (la función `main` o una función de inicialización específica). Este proceso se conoce como "fileless execution" y es mucho más difícil de detectar, ya que no deja rastros en el disco duro. La ejecución en memoria también es más rápida, ya que evita la latencia de las operaciones de E/S del sistema de archivos. El plugin, al ejecutarse, tendrá acceso a las mismas API y recursos que el agente principal, lo que le permitirá interactuar con el sistema operativo, la red y otros procesos de manera nativa. Al finalizar su tarea, el plugin puede liberar la memoria y terminar su ejecución, dejando el sistema en el mismo estado que antes, excepto por los efectos de su operación (por ejemplo, un ataque DDoS en curso).

#### 3.3.3. Integración de un Motor de Exploits Dinámico (Lua)

Para aumentar aún más la flexibilidad y la capacidad de respuesta ante la aparición de nuevas vulnerabilidades, el agente podría integrar un motor de scripts ligero, como Lua. Mientras que los plugins de ataque complejos se entregarían como binarios nativos, los exploits para vulnerabilidades más simples o recién descubiertas podrían ser entregados como scripts Lua. Lua es un lenguaje de scripting muy ligero y rápido, ideal para dispositivos embebidos con recursos limitados. El agente incluiría un intérprete de Lua embebido. Los operadores de la botnet podrían enviar scripts Lua que implementen la lógica de un exploit específico. Por ejemplo, un script podría construir y enviar una solicitud HTTP maliciosa para explotar un RCE en un dispositivo específico. El uso de Lua para los exploits ofrece varias ventajas: los scripts son más fáciles y rápidos de desarrollar y probar que los binarios nativos, lo que permite una respuesta más ágil a nuevas amenazas; los scripts son más pequeños que los binarios, lo que reduce el ancho de banda necesario para su distribución; y ofuscan la funcionalidad del exploit, ya que el código fuente no es directamente legible en el binario del agente. Este enfoque, inspirado en la botnet Reaper, que utilizó un motor Lua para sus exploits, convierte a la botnet en una plataforma de ataque verdaderamente adaptable y de rápida evolución.

## 4. Persistencia en Firmware y Resistencia a Análisis

La persistencia en el firmware de dispositivos embebidos representa el pináculo de la sofisticación en el diseño de malware para IoT. A diferencia de la persistencia tradicional en sistemas operativos de propósito general, donde los vectores de supervivencia post-reinicio son relativamente bien conocidos, los dispositivos IoT presentan un desafío único debido a su arquitectura de hardware cerrada, la diversidad de sus sistemas operativos y, crucialmente, la presencia de mecanismos de "restablecimiento de fábrica" diseñados para erradicar toda la configuración y software malicioso. Por lo tanto, lograr una persistencia que sobreviva a un restablecimiento de fábrica no es simplemente una cuestión de reinscribirse en los scripts de inicio, sino de comprometer las capas más bajas y fundamentales del software del dispositivo. Este nivel de persistencia convierte a un dispositivo comprometido en un activo de confianza para el atacante, capaz de resistir los intentos más comunes de remediación por parte del usuario o del proveedor. La investigación en este campo es crítica para desarrollar contramedidas efectivas, ya que un dispositivo que no puede ser limpiado mediante un restablecimiento de fábrica representa una vulnerabilidad permanente en la red del usuario.

### 4.1. Técnicas de Persistencia Anti-Reset



#### 4.1.2. Inyección en Procesos de Red (`netd`, `dnsmasq`)

Una técnica de persistencia más sutil, aunque menos resistente que la modificación del bootloader, consiste en la inyección de código en procesos de red críticos que son esenciales para el funcionamiento del dispositivo y que se reinician automáticamente si se detecta alguna anomalía. Procesos como `netd` (el demonio de red en sistemas Android y algunos Linux embebidos) o `dnsmasq` (un servidor DHCP y DNS ligero común en routers) son objetivos ideales para este tipo de ataque. Al inyectar el código malicioso en estos procesos, el malware puede asegurar su ejecución continua y, al mismo tiempo, pasar desapercibido, ya que estos procesos son legítimos y su presencia es esperada. La inyección puede realizarse de varias maneras, como la modificación de los binarios en el sistema de archivos o el uso de técnicas de hookeo en tiempo de ejecución. Una vez inyectado, el malware puede monitorear el tráfico de red, redirigir las consultas DNS, o incluso abrir puertos para permitir el acceso remoto, todo mientras se oculta dentro de un proceso legítimo. La ventaja de este enfoque es que no requiere la modificación de las particiones de arranque, lo que reduce el riesgo de "brickear" el dispositivo. Sin embargo, su principal desventaja es que puede ser más fácil de detectar por parte de software de seguridad que analice el comportamiento de los procesos, y puede no sobrevivir a una actualización de firmware que reemplace los binarios comprometidos.

#### 4.1.3. Hookeo de Syscalls con `LD_PRELOAD`

El hookeo de llamadas al sistema (syscalls) mediante la variable de entorno `LD_PRELOAD` es una técnica de persistencia y evasión que aprovecha una característica del cargador de enlaces dinámicos de Linux. Esta técnica permite a un atacante cargar una biblioteca compartida personalizada antes que cualquier otra biblioteca del sistema, incluyendo la biblioteca estándar de C (`libc`). Al hacerlo, el atacante puede "interceptar" o "hookear" las llamadas a funciones de la biblioteca estándar, como `read`, `write`, `open`, `connect`, etc., y reemplazar su comportamiento con una versión personalizada. Esto es especialmente útil en dispositivos con firmware no firmado, donde no se verifica la integridad de las bibliotecas del sistema. La biblioteca maliciosa puede ser diseñada para ocultar la presencia del malware, por ejemplo, ocultando los archivos y procesos relacionados con la infección cuando se listan con comandos como `ls` o `ps`. También puede ser utilizada para crear un backdoor, por ejemplo, interceptando las llamadas a `accept` en el servidor SSH para permitir el acceso sin autenticación a un atacante que conozca una contraseña secreta. La persistencia se logra configurando la variable `LD_PRELOAD` de manera que apunte a la biblioteca maliciosa en los scripts de inicio del sistema, como `/etc/rc.local` o en los archivos de configuración del shell para usuarios específicos.

### 4.2. Análisis de Persistencia por Modelo de Router

El análisis de técnicas de persistencia debe ser específico para cada modelo de router, ya que la arquitectura del hardware, el sistema operativo embebido y el proceso de arranque pueden variar significativamente entre fabricantes e incluso entre modelos del mismo fabricante. Un análisis detallado de los modelos más populares, como el TP-Link Archer C7 y el Comcast Xfinity XB7, es crucial para entender las vulnerabilidades específicas que pueden ser explotadas para lograr la persistencia. Este análisis implica la extracción y el análisis del firmware, la identificación de los componentes del sistema de arranque (bootloader, kernel, sistema de archivos), y la investigación de las vulnerabilidades conocidas y los vectores de ataque que podrían permitir la modificación del firmware o la inyección de código. La información obtenida de este análisis permite a los investigadores en ciberseguridad desarrollar herramientas y técnicas de detección específicas para cada modelo, así como recomendaciones de mitigación para los usuarios y los fabricantes.

#### 4.2.1. TP-Link Archer C7

El TP-Link Archer C7 es un router doméstico popular que ha sido objeto de múltiples investigaciones de seguridad debido a las vulnerabilidades encontradas en su firmware. Un análisis de persistencia en este modelo requiere una comprensión profunda de su arquitectura de hardware y software. El firmware del Archer C7, como el de muchos routers, está basado en Linux y utiliza un bootloader como U-Boot. La persistencia puede lograrse explotando vulnerabilidades que permitan la escritura en la memoria flash, donde se almacenan el bootloader y el sistema de archivos. Por ejemplo, si se descubre una vulnerabilidad de ejecución remota de código (RCE) en el servicio web del router, un atacante podría utilizarla para flashear una imagen de firmware modificada que incluya un backdoor. La investigación sobre el gusano UbootKit demuestra que es posible modificar el bootloader para lograr una persistencia que sobreviva a un restablecimiento de fábrica, una técnica que podría ser aplicada al Archer C7 si se encuentra un vector de ataque adecuado . Además, técnicas como la inyección de código en procesos de red como `dnsmasq` o el hookeo de syscalls con `LD_PRELOAD` también son viables, siempre que el atacante obtenga acceso root al sistema.

#### 4.2.2. Comcast Xfinity XB7

El análisis de persistencia en el router Comcast Xfinity XB7 presenta un conjunto diferente de desafíos y oportunidades en comparación con el TP-Link Archer C7. El XB7 es un dispositivo proporcionado por el proveedor de servicios de Internet (ISP), lo que a menudo significa que su firmware es más cerrado y puede tener implementadas medidas de seguridad más estrictas. Sin embargo, esto no lo hace inmune a las técnicas de persistencia. Un análisis de este modelo requeriría la obtención de una copia de su firmware, lo que puede ser más difícil que con routers de consumo estándar. Una vez obtenido el firmware, el proceso de análisis sería similar: identificar la arquitectura del hardware (probablemente ARM), el bootloader, el kernel de Linux y el sistema de archivos. La investigación debería centrarse en buscar vulnerabilidades en los servicios expuestos, como el servidor web de administración, el servicio TR-069 (utilizado para la gestión remota por parte del ISP) o cualquier otro servicio que esté escuchando en puertos abiertos. Si se encuentra una vulnerabilidad que permita la ejecución de código arbitrario, el siguiente paso sería explorar las técnicas de persistencia disponibles.

#### 4.2.3. Otros Modelos Populares

El análisis de persistencia no debe limitarse a solo dos modelos. Es crucial extender la investigación a una gama más amplia de dispositivos populares para entender la diversidad de vectores de ataque y técnicas de persistencia. Algunos otros modelos de routers y dispositivos IoT que serían objetivos prioritarios para el análisis incluyen:

*   **Routers de consumo:** Netgear Nighthawk, ASUS RT-AX series, Linksys WRT series, TP-Link
*   **Cámaras IP:** Hikvision, Dahua, Axis.
*   **DVRs/NVRs:** Tiandy, Uniview, QNAP, Synology.

Para cada uno de estos modelos, el proceso de análisis seguiría la misma metodología: adquisición del firmware, análisis estático y dinámico, identificación de vulnerabilidades y prueba de técnicas de persistencia. La creación de una base de datos de estos análisis permitiría a los investigadores identificar patrones y tendencias en la seguridad de los dispositivos IoT, así como desarrollar herramientas de detección y mitigación más generales.

### 4.3. Defensa Contra Análisis y Evasión

La defensa contra el análisis y la evasión de mecanismos de seguridad son componentes críticos de un agente de botnet avanzado. Un agente bien diseñado debe ser capaz de detectar cuando se está ejecutando en un entorno de análisis, como una máquina virtual (VM) o un sandbox, y modificar su comportamiento en consecuencia para evitar ser detectado. Además, debe ser capaz de ocultar su comunicación con la red de comando y control (C&C) mezclándose con el tráfico legítimo del dispositivo. Finalmente, para maximizar su supervivencia y eficacia, el agente debe ser capaz de defender su territorio, bloqueando la infección por parte de otros malwares competidores, una técnica observada en botnets como Hajime. Estas capacidades de defensa y evasión son esenciales para garantizar la longevidad de la botnet y su capacidad para operar de manera sigilosa y efectiva.

#### 4.3.1. Detección de Entornos de Análisis (Sandbox, VM)

La detección de entornos de análisis es una técnica fundamental para que el malware evada la detección por parte de los investigadores y los sistemas de seguridad. Los entornos de análisis, como las máquinas virtuales (VM) y los sandboxes, a menudo presentan características y comportamientos que los distinguen de un sistema físico real. Un agente de botnet avanzado puede ser diseñado para buscar estas anomalías y, si las detecta, alterar su comportamiento para parecer inofensivo o simplemente no ejecutarse. Algunas de las técnicas de detección más comunes incluyen la verificación de sensores de hardware, la medición de los tiempos de respuesta del sistema y la búsqueda de artefactos específicos del software de virtualización. Por ejemplo, un agente puede intentar leer la temperatura del CPU o la velocidad del ventilador; si estos valores son inexistentes o anómalos, es probable que se esté ejecutando en una VM. Del mismo modo, puede medir el tiempo que tarda el sistema en realizar ciertas operaciones, ya que las VMs a menudo presentan una latencia mayor que los sistemas físicos. Finalmente, el agente puede buscar en el sistema archivos, procesos o controladores específicos de software de virtualización como VMware, VirtualBox o QEMU.

#### 4.3.2. Obfuscación de Tráfico (Emulación ONVIF)

La obfuscación del tráfico de red es una técnica crucial para que un agente de botnet evada la detección por parte de los sistemas de detección de intrusiones (IDS) y los firewalls. En lugar de utilizar protocolos de comunicación personalizados y fácilmente detectables, un agente avanzado puede diseñarse para mezclar su tráfico de comando y control (C&C) con el tráfico legítimo del dispositivo. Un ejemplo de esta técnica es la emulación del protocolo **ONVIF (Open Network Video Interface Forum)** , que es un estándar de la industria para la comunicación entre dispositivos de videovigilancia IP, como cámaras y grabadoras de video (DVR/NVR). Al emular el tráfico ONVIF, el agente puede hacer que su comunicación con el C&C parezca ser un intercambio legítimo de información entre una cámara y un cliente de gestión de video. Esto es particularmente eficaz cuando el dispositivo infectado es una cámara IP o un DVR, ya que el tráfico ONVIF es esperado y, por lo tanto, menos probable que sea inspeccionado de cerca.

#### 4.3.3. Bloqueo de Infecciones Competidoras (Hajime-style)

Para maximizar los recursos de un dispositivo comprometido y evitar conflictos con otros malwares, el agente implementará un mecanismo de defensa contra infecciones competidoras, una técnica popularizada por la botnet Hajime. Después de infectar un dispositivo, el agente bloqueará los puertos de servicios de administración comunes, como **Telnet (puerto 23) y SSH (puerto 22)** . Al ocupar estos puertos, el agente evita que otras botnets que utilizan vectores de ataque similares puedan acceder al dispositivo y competir por el control. Además del bloqueo de puertos, el agente puede implementar una "lista negra" de procesos conocidos de otras botnets. Monitoreará constantemente los procesos en ejecución y, si detecta uno que coincida con un nombre en su lista, lo terminará inmediatamente. Este comportamiento defensivo asegura que el dispositivo permanezca bajo el control exclusivo de la botnet, maximizando su tiempo de actividad y su capacidad para participar en ataques coordinados.

## 5. Integración de Vulnerabilidades y Explotación

### 5.1. Base de Datos de CVEs para IoT

La capacidad de explotar vulnerabilidades conocidas (CVEs) es un componente fundamental de la estrategia de propagación del agente. Para ser efectivo, el agente debe mantener una base de datos actualizada y relevante de vulnerabilidades que afecten a dispositivos IoT populares. La creación y mantenimiento de esta base de datos es un proceso continuo que requiere la automatización de la búsqueda y el filtrado de información de fuentes públicas de vulnerabilidades.

#### 5.1.2. Filtrado por Dispositivos Embebidos

No todas las vulnerabilidades son relevantes para el objetivo de la botnet. La búsqueda de la NVD API debe ser filtrada para identificar aquellas que afecten específicamente a dispositivos embebidos, como routers, cámaras IP, DVRs y otros dispositivos IoT. El filtrado se puede realizar utilizando palabras clave en la descripción de la vulnerabilidad, como los nombres de los fabricantes (por ejemplo, "TP-Link", "Dahua"), los tipos de dispositivos (por ejemplo, "router", "camera", "DVR") o los nombres de los servicios de software afectados (por ejemplo, "Telnet", "HTTP", "TR-064"). Este proceso de filtrado es crucial para mantener la base de datos de exploits del agente enfocada y eficiente.

#### 5.1.3. Generación de Base de Datos de Banners Vulnerables

Una vez que se ha identificado un CVE relevante, el siguiente paso es determinar cómo detectar si un dispositivo es vulnerable. Muchas vulnerabilidades están asociadas con una versión específica de un software o firmware. El agente puede identificar esta versión analizando el "banner" que un servicio envía cuando se conecta a él. Por ejemplo, un servidor web podía enviar un banner como `Server: nginx/1.18.0`. La base de datos de la botnet contendrá una lista de estos banners vulnerables, mapeados a sus CVEs correspondientes. Cuando el agente realiza el escaneo de servicios, compara los banners que recibe con su base de datos para determinar si un dispositivo es vulnerable y, por lo tanto, un objetivo para la explotación.

### 5.2. Top 5 CVEs para Integración

A continuación, se presenta una lista de cinco CVEs que serían candidatos prioritarios para la integración en la base de datos de exploits del agente. Estos CVEs han sido seleccionados por su gravedad (ejecución remota de código), su prevalencia en dispositivos IoT populares y la disponibilidad de pruebas de concepto (PoCs) públicas.

| CVE ID | Descripción | Dispositivos Afectados | Severidad |
| :--- | :--- | :--- | :--- |
| **CVE-2023-26609** | Vulnerabilidad de ejecución remota de código en el servicio web de ciertos routers. | Routers residenciales de múltiples marcas. | Alta |
| **CVE-2024-6047** | Vulnerabilidad de inyección de comandos en la interfaz de administración de dispositivos de red. | Switches y routers gestionados. | Alta |
| **CVE-2024-20345** | Vulnerabilidad de RCE en el firmware de cámaras IP de una marca popular. | Cámaras IP Dahua y marcas OEM. | Alta |
| **CVE-2020-10882/10883** | Vulnerabilidades de RCE en el servidor web de routers TP-Link Archer. | TP-Link Archer C5, C7, C9, etc. | Alta |
| **CVE-2021-36260** | Vulnerabilidad de RCE en el servicio de actualización de firmware de cámaras Hikvision. | Cámaras IP Hikvision y marcas OEM. | Alta |

#### 5.2.1. CVE-2023-26609

Este CVE representa una vulnerabilidad crítica en el servicio web de una amplia gama de routers residenciales. Permite a un atacante no autenticado ejecutar código arbitrario en el dispositivo con privilegios elevados. La explotación típicamente involucra el envío de una solicitud HTTP maliciosa que abusa de una función de procesamiento de datos del servidor. La integración de este exploit sería de alto valor para la botnet, ya que permitiría la infección masiva de routers domésticos, que son un objetivo primario para la persistencia y el control de la red.

#### 5.2.2. CVE-2024-6047

Esta vulnerabilidad afecta a dispositivos de red más sofisticados, como switches y routers gestionados. Aunque estos dispositivos no son tan comunes en hogares, su compromiso puede ser muy valioso para un atacante, ya que a menudo se encuentran en redes empresariales y pueden proporcionar un punto de entrada a infraestructuras más críticas. La vulnerabilidad es una inyección de comandos en la interfaz de administración, lo que permite la ejecución de código con los privilegios del servicio web.

#### 5.2.3. CVE-2024-20345 (Cámaras Dahua)

Este CVE es un ejemplo de una vulnerabilidad específica de un fabricante de cámaras IP muy popular. Permite la ejecución remota de código sin autenticación, lo que la hace extremadamente peligrosa. Dado que las cámaras IP a menudo tienen una conectividad directa a Internet y pueden ser utilizadas para vigilancia, su compromiso es una grave violación de la privacidad. La integración de este exploit permitiría a la botnet construir una red masiva de dispositivos de videovigilancia comprometidos.

#### 5.2.4. CVE-2020-10882/10883 (TP-Link Archer)

Estas vulnerabilidades afectan a una línea muy popular de routers domésticos de TP-Link. Permiten la ejecución remota de código a través del servidor web del dispositivo. Aunque son vulnerabilidades más antiguas, muchos usuarios no actualizan el firmware de sus routers, lo que significa que una gran cantidad de dispositivos sigue siendo vulnerable. La explotación de estas vulnerabilidades ha sido ampliamente documentada y ha sido utilizada por varias botnets en el pasado.

#### 5.2.5. Otros CVEs Relevantes

Además de los cinco CVEs anteriores, la base de datos del agente debe ser dinámica y estar en constante expansión. Otros CVEs relevantes que deberían ser considerados para la integración incluyen vulnerabilidades en servicios como **Telnet, SSH, FTP y SNMP**, que son comunes en dispositivos IoT. También es importante monitorear las vulnerabilidades en los protocolos de descubrimiento y gestión, como **UPnP, SSDP y TR-064**, que a menudo se encuentran activos en routers residenciales.

### 5.3. Desarrollo de PoCs Modificados

Una vez que se ha seleccionado un CVE para la integración, el siguiente paso es desarrollar una prueba de concepto (PoC) funcional que pueda ser utilizada por el agente. Estos PoCs no serán simplemente copias de los scripts públicos disponibles, sino que serán modificados y optimizados para su uso en el contexto de la botnet.

#### 5.3.1. Adaptación para Integración con el Agente

El PoC debe ser adaptado para que pueda ser ejecutado por el módulo de explotación del agente. Esto significa que debe ser un binario independiente o un script que pueda ser llamado con parámetros específicos (por ejemplo, la dirección IP y el puerto del objetivo). El PoC debe ser robusto y manejar errores de manera elegante, sin causar fallos que puedan ser detectados por el sistema objetivo. Además, si el agente utiliza un motor de scripts como Lua, el PoC podría ser portado a este lenguaje para permitir una mayor flexibilidad y facilidad de actualización.

#### 5.3.2. Optimización para Recursos Limitados

Los dispositivos IoT tienen recursos limitados, por lo que el PoC debe ser lo más ligero y eficiente posible. Esto puede implicar la reescritura del código en un lenguaje de bajo nivel como C o Rust, en lugar de utilizar scripts de alto nivel como Python. El binario resultante debe ser pequeño y tener un bajo consumo de memoria y CPU. Además, el PoC debe ser cuidadosamente probado en un entorno de laboratorio que emule las condiciones de un dispositivo IoT real para asegurar su fiabilidad y eficacia.

## 6. Entregables y Referencias Técnicas

### 6.1. Reporte Técnico Interno

Como parte del proceso de investigación y desarrollo, se generará un reporte técnico interno que documente los hallazgos y el diseño de la botnet. Este reporte servirá como una referencia para el equipo de investigación y como base para el desarrollo de contramedidas.

#### 6.1.1. Diseño del Protocolo P2P

El reporte incluirá una especificación detallada del protocolo de comunicación P2P, incluyendo el formato de los mensajes, el algoritmo de DHT utilizado, el esquema de cifrado y los mecanismos de fallback. Esta documentación es crucial para entender la resiliencia de la botnet y para desarrollar estrategias para su desmantelamiento.

#### 6.1.2. Análisis de Técnicas de Persistencia

El reporte documentará el análisis de las técnicas de persistencia anti-reset, incluyendo los resultados del análisis de firmware de diferentes modelos de routers. Esta información es vital para desarrollar herramientas de detección y remediación que puedan limpiar los dispositivos infectados de manera efectiva.

#### 6.1.3. Integración de Capacidades de Ataque (DDoS, RCE)

El reporte describirá las capacidades de ataque de la botnet, incluyendo los tipos de ataques DDoS que puede lanzar, las técnicas de robo de datos y las capacidades de ejecución remota de código (RCE). Esta información es fundamental para evaluar el impacto potencial de la botnet y para desarrollar defensas específicas contra sus vectores de ataque.

### 6.2. Código de Referencia

Se desarrollará un conjunto de herramientas y scripts de referencia en Rust para facilitar la simulación y el análisis de la botnet. Estas herramientas no serán parte del agente malicioso en sí, sino que servirán para probar y validar los diferentes componentes del sistema.

#### 6.2.1. Escáner de Subredes en Rust

Una herramienta de línea de comandos que implemente el módulo de escaneo de puertos y servicios del agente. Esta herramienta permitirá a los investigadores cartografiar redes locales y remotas para identificar dispositivos IoT vulnerables.

#### 6.2.2. Cliente P2P Básico

Un cliente P2P simplificado que implemente el protocolo de comunicación y la DHT. Este cliente servirá para probar la resiliencia de la red P2P y para simular la propagación de comandos.

#### 6.2.3. Payload Autoextraíble para ARMv5

Un script o herramienta que genere payloads autoextraíbles para la arquitectura ARMv5. Estos payloads serán utilizados para probar el módulo de propagación y la ejecución de código en dispositivos emulados.

### 6.3. Diagramas de Arquitectura

Se crearán diagramas de arquitectura para visualizar el diseño y el flujo de operación de la botnet. Estos diagramas serán una parte integral de la documentación técnica y ayudarán a los investigadores a comprender rápidamente la complejidad del sistema.

#### 6.3.1. Secuencia de Infección

Un diagrama de secuencia que ilustre el flujo completo de la infección, desde el escaneo inicial hasta la integración del nuevo agente en la red P2P. Este diagrama mostrará la interacción entre los diferentes módulos del agente y los pasos clave del proceso de autoreplicación.

#### 6.3.2. Arquitectura Híbrida HTTP/P2P

Un diagrama de arquitectura que muestre la estructura de la red de comunicación, incluyendo la red P2P descentralizada y los mecanismos de fallback HTTP. Este diagrama ilustrará la resiliencia de la infraestructura de comando y control y los diferentes canales de comunicación disponibles para los operadores.
