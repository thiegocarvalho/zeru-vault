# Avisos de terceiros

🇧🇷 Português · [🇺🇸 English](THIRD-PARTY-NOTICES.en.md)

O código do Zeru Vault é licenciado sob a [MIT](LICENSE). O **firmware compilado** também contém componentes de terceiros, cada um com sua própria licença:

| Componente | Usado para | Licença |
| :--- | :--- | :--- |
| [arduino-esp32](https://github.com/espressif/arduino-esp32) 3.3.x | Núcleo Arduino para o ESP32-S3 | LGPL-2.1-only |
| [ESP-IDF](https://github.com/espressif/esp-idf) (embutido no núcleo) | Sistema, drivers, NVS, eFuse, HMAC | Apache-2.0 |
| FreeRTOS (no ESP-IDF) | Sistema operacional de tempo real | MIT |
| Mbed TLS (no ESP-IDF) | AES-GCM, PBKDF2, SHA-256, ECDSA P-256 | Apache-2.0 |
| libsodium (no ESP-IDF) | Ed25519, comparação em tempo constante, zeroização | ISC |
| TinyUSB (no núcleo) | USB HID (FIDO2) e CDC serial | MIT |
| [GFX Library for Arduino](https://github.com/moononournation/Arduino_GFX) 1.6.x | Desenho no display | BSD (derivada da Adafruit GFX) |
| Fontes em `firmware/fonts/` | Texto na tela | **GPL-3.0-or-later** com exceção para fontes (GNU FreeFont), veja [`firmware/fonts/LICENSE.md`](firmware/fonts/LICENSE.md) |

## O que isso implica

- **Código-fonte:** você pode usar, modificar e redistribuir o código deste repositório sob a licença MIT.
- **Binário do firmware:** por causa das fontes GNU FreeFont, trate um `.bin` compilado como distribuído sob a **GPL-3.0-or-later**: ao distribuí-lo, ofereça também o código-fonte correspondente e o texto da GPL. Como o projeto inteiro é aberto e pode ser recompilado com `make build`, isso também atende à exigência da LGPL-2.1 do núcleo arduino-esp32 (permitir que o usuário gere o firmware com uma versão modificada da biblioteca).
- **Para ter um binário só com licenças permissivas**, troque as fontes por fontes SIL OFL, Apache-2.0 ou Bitstream Vera/DejaVu, convertidas com o `fontconvert` da Adafruit.
- O agente Python (`agent/`) usa apenas a biblioteca padrão do Python. O gerador de capturas de tela (`tools/ui-sim/`) usa o Pillow apenas na máquina do desenvolvedor; nada disso vai para o firmware.

Isto é uma descrição de boa-fé, não aconselhamento jurídico.
